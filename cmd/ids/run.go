package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/bUrn-1337/intrusion-detection-system/internal/capture"
	"github.com/bUrn-1337/intrusion-detection-system/internal/logging"
	"github.com/bUrn-1337/intrusion-detection-system/internal/logging/tui"
	"github.com/bUrn-1337/intrusion-detection-system/internal/packet"
	"github.com/bUrn-1337/intrusion-detection-system/internal/parser/app"
	"github.com/bUrn-1337/intrusion-detection-system/internal/parser/lower"
	"github.com/bUrn-1337/intrusion-detection-system/internal/parser/upper"
	"github.com/bUrn-1337/intrusion-detection-system/internal/rules"
	"github.com/bUrn-1337/intrusion-detection-system/internal/stream"
)

const (
	defaultLog   = "ids-alerts.jsonl"
	defaultRules = "rules.conf"
)

type runOptions struct {
	capture       capture.Config
	rules         string
	whitelist     []netip.Prefix
	log           logging.WriterConfig
	noTUI         bool
	statsInterval time.Duration
	pprof         string
	stream        stream.Config
}

func runIDS(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	opt := runOptions{capture: capture.DefaultConfig()}
	fs := flag.NewFlagSet("ids run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&opt.capture.Interface, "i", "", "network `interface` for live capture")
	fs.StringVar(&opt.capture.PcapFile, "r", "", "pcap `file` to read")
	fs.StringVar(&opt.capture.BPFFilter, "f", "", "BPF filter expression")
	fs.StringVar(&opt.rules, "rules", defaultRules, "rules file (SIGHUP or the r key reloads it)")
	fs.Func("whitelist", "comma-separated source `CIDR`s or addresses that never alert", func(v string) error {
		for _, item := range strings.Split(v, ",") {
			p, err := logging.ParsePrefix(strings.TrimSpace(item))
			if err != nil {
				return fmt.Errorf("bad whitelist entry: %w", err)
			}
			opt.whitelist = append(opt.whitelist, p)
		}
		return nil
	})
	fs.StringVar(&opt.log.Path, "log", defaultLog, "alert log `file` (JSON Lines)")
	opt.log.MaxSize = logging.DefaultMaxSize
	fs.Func("log-max-size", "rotate the log when it would exceed `SIZE` bytes (suffix K, M or G; default 100M)", func(v string) (err error) {
		opt.log.MaxSize, err = parseSize(v)
		return err
	})
	fs.IntVar(&opt.log.MaxFiles, "log-max-files", logging.DefaultMaxFiles, "rotated log files to keep")
	fs.BoolVar(&opt.noTUI, "no-tui", false, "no dashboard: print alerts to stdout, one line each (automatic when stdout is not a terminal)")
	fs.DurationVar(&opt.statsInterval, "stats-interval", time.Minute, "how often a stats record is logged")
	fs.StringVar(&opt.pprof, "pprof", "", "serve net/http/pprof on `ADDR` for diagnostics; must be 127.0.0.1:PORT")
	fs.Func("stream-ports", "TCP `PORT/PROTO` list the stream stage reassembles, PROTO one of http, dns, ftp, tls, or \"none\" (default 21/ftp,53/dns,80/http,443/tls,8000/http,8080/http,8443/tls)", func(v string) (err error) {
		opt.stream.Ports, err = parseStreamPorts(v)
		return err
	})
	fs.Func("stream-max-mem", "memory `SIZE` for TCP reassembly over all flows; least recently used flows are dropped beyond it (default 64M)", func(v string) error {
		n, err := parseSize(v)
		if err == nil && n > 1<<40 {
			err = fmt.Errorf("bad size %q (at most 1T)", v)
		}
		opt.stream.MaxBytes = int(n)
		return err
	})
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "ids run: unexpected arguments %q\n", fs.Args())
		return 2
	}
	if (opt.capture.Interface == "") == (opt.capture.PcapFile == "") {
		fmt.Fprintln(stderr, "ids run: give exactly one of -i IFACE (live capture) or -r FILE (pcap file)")
		return 2
	}
	if opt.log.MaxFiles < 1 {
		fmt.Fprintln(stderr, "ids run: -log-max-files must be at least 1")
		return 2
	}
	if opt.statsInterval <= 0 {
		fmt.Fprintln(stderr, "ids run: -stats-interval must be positive")
		return 2
	}
	if opt.pprof != "" {
		if err := checkPprofAddr(opt.pprof); err != nil {
			fmt.Fprintln(stderr, "ids run:", err)
			return 2
		}
	}
	if f, ok := stdout.(*os.File); !ok || !term.IsTerminal(int(f.Fd())) {
		opt.noTUI = true
	}
	if err := runPipeline(ctx, opt, stdout, stderr); err != nil {
		fmt.Fprintln(stderr, "ids:", err)
		return 1
	}
	return 0
}

// parseStreamPorts parses -stream-ports: "none", or comma-separated
// PORT/PROTO items such as "80/http,5353/dns".
func parseStreamPorts(v string) (map[uint16]stream.Proto, error) {
	ports := map[uint16]stream.Proto{}
	if strings.TrimSpace(v) == "none" {
		return ports, nil
	}
	for _, item := range strings.Split(v, ",") {
		ps, name, ok := strings.Cut(strings.TrimSpace(item), "/")
		port, err := strconv.ParseUint(ps, 10, 16)
		proto, known := stream.ParseProto(strings.ToUpper(name))
		if !ok || err != nil || port == 0 || !known {
			return nil, fmt.Errorf("bad stream port %q (want PORT/PROTO, PROTO one of http, dns, ftp, tls)", item)
		}
		ports[uint16(port)] = proto
	}
	return ports, nil
}

// parseSize parses a byte count with an optional K, M or G suffix (powers
// of 1024; a trailing B or iB is allowed).
func parseSize(v string) (int64, error) {
	s := strings.ToUpper(strings.TrimSpace(v))
	s = strings.TrimSuffix(strings.TrimSuffix(s, "B"), "I")
	mult := int64(1)
	if n := len(s); n > 0 {
		switch s[n-1] {
		case 'K':
			mult = 1 << 10
		case 'M':
			mult = 1 << 20
		case 'G':
			mult = 1 << 30
		}
		if mult > 1 {
			s = s[:n-1]
		}
	}
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil || n <= 0 || n > (1<<62)/mult {
		return 0, fmt.Errorf("bad size %q (want e.g. 2048, 512K, 100M)", v)
	}
	return n * mult, nil
}

func loadRules(path string) (*rules.RuleSet, error) {
	rs, err := rules.Load(path)
	var le *rules.LoadError
	switch {
	case err == nil:
		return rs, nil
	case errors.Is(err, fs.ErrNotExist):
		return nil, fmt.Errorf("rules file %s not found (use -rules PATH)", path)
	case errors.Is(err, fs.ErrPermission):
		return nil, fmt.Errorf("rules file %s is not readable: permission denied", path)
	case errors.As(err, &le):
		return nil, fmt.Errorf("bad rules in %s, nothing started:\n%s", path, reloadError(err))
	}
	return nil, fmt.Errorf("reading rules: %w", err)
}

// logOpenError explains why the alert log could not be opened.
func logOpenError(path string, err error) error {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("cannot create alert log %s: directory %s does not exist (create it or use -log PATH)", path, filepath.Dir(path))
	case errors.Is(err, fs.ErrPermission):
		return fmt.Errorf("cannot open alert log %s: permission denied (use -log PATH)", path)
	}
	return fmt.Errorf("cannot open alert log %s: %w", path, err)
}

// reloadError formats a rules error with one problem per line.
func reloadError(err error) string {
	var le *rules.LoadError
	if errors.As(err, &le) {
		lines := make([]string, len(le.Errors))
		for i, se := range le.Errors {
			lines[i] = se.Error()
		}
		return strings.Join(lines, "\n")
	}
	if errors.Is(err, fs.ErrNotExist) {
		return "rules file not found: " + err.Error()
	}
	return err.Error()
}

// ids is one run of the pipeline.
type ids struct {
	opt    runOptions
	stdout io.Writer
	stderr io.Writer

	cap    *capture.Capturer
	stream *stream.Reassembler
	eng    *rules.Engine
	log    *logging.Writer
	agg    *logging.Aggregator
	dash   *tui.Dashboard // nil with -no-tui
	source string
	start  time.Time

	hmu    sync.Mutex
	header tui.Header

	reloadReq chan struct{}
}

func runPipeline(ctx context.Context, opt runOptions, stdout, stderr io.Writer) error {
	rs, err := loadRules(opt.rules)
	if err != nil {
		return err
	}
	if opt.pprof != "" {
		stop, err := servePprof(opt.pprof, stderr)
		if err != nil {
			return err
		}
		defer stop()
	}
	c, err := capture.New(opt.capture)
	if err != nil {
		return err // capture's messages already say what to do
	}
	defer c.Close()
	w, err := logging.NewWriter(opt.log)
	if err != nil {
		return logOpenError(opt.log.Path, err)
	}

	d := &ids{
		opt: opt, stdout: stdout, stderr: stderr,
		cap: c, stream: stream.New(opt.stream), eng: rules.NewEngine(rs, rules.EngineConfig{Whitelist: opt.whitelist}), log: w,
		start: time.Now(), reloadReq: make(chan struct{}, 1),
	}
	d.agg = logging.NewAggregator(logging.AggregatorConfig{}, d.start)
	d.source = "interface " + opt.capture.Interface
	if opt.capture.PcapFile != "" {
		d.source = "file " + opt.capture.PcapFile
	}
	d.header = tui.Header{Source: d.source, Started: d.start, Rules: rs.Len()}
	if !opt.noTUI {
		d.dash = tui.New(tui.Sources{
			Snapshot: d.agg.Snapshot,
			Header:   d.getHeader,
			Health:   d.health,
			Reload:   d.requestReload,
		}, 0)
	} else {
		fmt.Fprintf(stderr, "ids: %d rules from %s, reading %s, logging to %s\n", rs.Len(), opt.rules, d.source, opt.log.Path)
	}
	d.feedEvents(d.start)

	// Capture runs until ctx is cancelled (signal, q) or the file ends.
	capCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	go d.reloader(capCtx, hup)

	pipeDone := make(chan struct{})
	go func() {
		defer close(pipeDone)
		d.pipeline(c.Start(capCtx))
	}()

	var uiErr error
	if d.dash != nil {
		go func() {
			<-capCtx.Done() // SIGINT/SIGTERM
			d.dash.Stop()
		}()
		uiErr = d.dash.Run(nil)
		cancel()
	}
	<-pipeDone
	cancel()

	if err := w.Close(); err != nil {
		fmt.Fprintln(stderr, "ids: log:", err)
	}
	if d.dash == nil || uiErr != nil {
		d.printFinal()
	}
	if uiErr != nil {
		return fmt.Errorf("dashboard: %w", uiErr)
	}
	return c.Err()
}

// pipeline is the one goroutine that parses and inspects packets, in
// capture order: parsing in parallel would reorder packets and break the
// engine's handshake tracking. It returns after pkts is closed and
// drained, having flushed the engine and logged the final stats.
func (d *ids) pipeline(pkts <-chan *packet.ParsedPacket) {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	statsTick := time.NewTicker(d.opt.statsInterval)
	defer statsTick.Stop()
	for {
		select {
		case p, ok := <-pkts:
			if !ok {
				d.shutdown()
				return
			}
			lower.Parse(p)
			upper.Parse(p)
			d.stream.Process(p)
			app.Parse(p)
			d.agg.Packet(p)
			d.emit(d.eng.Process(p))
			if ns := d.eng.TakeNotices(); ns != nil {
				d.notices(ns)
			}
		case now := <-tick.C:
			d.agg.Tick(now)
		case now := <-statsTick.C:
			d.log.WriteStats(d.statsRecord(now, logging.StatsPeriodic))
		}
	}
}

// shutdown flushes the engine's pending summaries into the log before the
// final stats record, so nothing the engine held is lost.
func (d *ids) shutdown() {
	d.emit(d.eng.Flush())
	now := time.Now()
	d.agg.Tick(now)
	d.log.WriteStats(d.statsRecord(now, logging.StatsShutdown))
	d.hmu.Lock()
	d.header.Done = d.opt.capture.PcapFile != ""
	d.hmu.Unlock()
}

func (d *ids) emit(alerts []rules.Alert) {
	for _, a := range alerts {
		d.log.WriteAlert(a)
		d.agg.Alert(a)
		if d.dash != nil {
			d.dash.SendAlert(a)
		} else {
			fmt.Fprintln(d.stdout, logging.FormatAlert(a))
		}
	}
}

func (d *ids) statsRecord(now time.Time, reason string) logging.StatsRecord {
	cs := d.cap.Stats()
	s := d.eng.Stats()
	es := logging.EngineStatsFrom(s)
	es.Feeds = logging.FeedStatsFrom(s.Feeds, now)
	return logging.StatsRecord{
		Time: now, Reason: reason, Uptime: now.Sub(d.start).Seconds(), Source: d.source,
		Capture: logging.CaptureStats{Captured: cs.Captured, KernelDropped: cs.KernelDropped, QueueDropped: cs.QueueDropped, QueueDepth: cs.QueueDepth},
		Engine:  es,
		Stream:  logging.StreamStatsFrom(d.stream.Stats()),
		Traffic: d.agg.Totals(),
		Log:     d.log.Stats(),
	}
}

func (d *ids) printFinal() {
	cs := d.cap.Stats()
	es := d.eng.Stats()
	ls := d.log.Stats()
	ss := d.stream.Stats()
	fmt.Fprintf(d.stderr, "ids: captured=%d kernel_dropped=%d queue_dropped=%d rules=%d packets=%d alerts=%d summaries=%d incidents=%d log_written=%d log_dropped=%d\n",
		cs.Captured, cs.KernelDropped, cs.QueueDropped, es.Rules, es.Packets, es.Alerts, es.Summaries, es.Incidents, ls.Written, ls.Dropped)
	fmt.Fprintf(d.stderr, "ids: stream flows=%d messages=%d evictions=%d gaps=%d desyncs=%d resyncs=%d overlap_conflicts=%d oversize_headers=%d ooo_overflows=%d cap_drops=%d buffered_peak=%d\n",
		ss.FlowsTotal, ss.Messages, ss.Evictions, ss.Gaps, ss.Desyncs, ss.Resyncs, ss.OverlapConflicts, ss.OversizeHeaders, ss.OOOOverflows, ss.CapDrops, ss.BufferedPeak)
}

// notices logs the engine's notices (a baseline learning or active) as
// events.
func (d *ids) notices(ns []rules.Notice) {
	n := d.eng.Stats().Rules
	for _, x := range ns {
		d.log.WriteEvent(logging.EventRecord{Time: time.Now(), Event: logging.EventBaseline, OK: true, Rules: n, Path: d.opt.rules, Message: x.Message})
		if d.dash == nil {
			fmt.Fprintln(d.stderr, "ids:", x.Message)
		}
	}
}

func (d *ids) getHeader() tui.Header {
	d.hmu.Lock()
	h := d.header
	d.hmu.Unlock()
	h.Baseline = d.eng.BaselineStatus()
	return h
}

func (d *ids) health() tui.Health {
	cs := d.cap.Stats()
	ss := d.stream.Stats()
	return tui.Health{
		Captured: cs.Captured, KernelDropped: cs.KernelDropped, QueueDropped: cs.QueueDropped,
		QueueDepth: cs.QueueDepth, LogDropped: d.log.Stats().Dropped,
		StreamFlows: ss.Flows, StreamBuffered: ss.Buffered, StreamEvictions: ss.Evictions,
		StreamGaps: ss.Gaps, StreamDesyncs: ss.Desyncs, StreamOverlaps: ss.OverlapConflicts,
	}
}

// requestReload asks the reloader for a reload without blocking; a
// request made while one is pending is merged into it.
func (d *ids) requestReload() {
	select {
	case d.reloadReq <- struct{}{}:
	default:
	}
}

// reloader performs reloads requested by SIGHUP or the r key, logs the
// outcome as an event record and shows it in the header.
func (d *ids) reloader(ctx context.Context, hup <-chan os.Signal) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-hup:
		case <-d.reloadReq:
		}
		d.reload()
	}
}

func (d *ids) reload() {
	err := d.eng.Reload(d.opt.rules)
	now := time.Now()
	n := d.eng.Stats().Rules
	ev := logging.EventRecord{Time: now, Event: logging.EventReload, OK: err == nil, Rules: n, Path: d.opt.rules}
	summary := fmt.Sprintf("ok, %d rules", n)
	if err != nil {
		ev.Error = reloadError(err)
		first, _, _ := strings.Cut(ev.Error, "\n")
		summary = fmt.Sprintf("FAILED, kept %d rules: %s", n, first)
		if c := strings.Count(ev.Error, "\n"); c > 0 {
			summary += fmt.Sprintf(" (+%d more)", c)
		}
	}
	d.log.WriteEvent(ev)
	d.hmu.Lock()
	d.header.Rules, d.header.Reload, d.header.ReloadOK, d.header.ReloadAt = n, summary, err == nil, now
	d.hmu.Unlock()
	if d.dash == nil {
		if err != nil {
			fmt.Fprintf(d.stderr, "ids: reload of %s failed, keeping the previous %d rules:\n%s\n", d.opt.rules, n, ev.Error)
		} else {
			fmt.Fprintf(d.stderr, "ids: reloaded %d rules from %s\n", n, d.opt.rules)
		}
	}
	if err == nil {
		d.feedEvents(now)
	}
}

// feedEvents logs a warning event for every feed load warning and every
// stale feed of the rules just loaded, and shows the feeds in the header.
// Staleness is judged against wall time: a feed is as old as its file,
// whatever time the packets carry.
func (d *ids) feedEvents(now time.Time) {
	msgs := d.eng.Warnings()
	feeds := d.eng.Stats().Feeds
	status := make([]tui.FeedStatus, len(feeds))
	for i, f := range feeds {
		status[i] = tui.FeedStatus{Name: f.Name, Entries: f.Entries, ModTime: f.ModTime, MaxAge: f.MaxAge}
		if age := now.Sub(f.ModTime); f.MaxAge > 0 && age > f.MaxAge {
			msgs = append(msgs, fmt.Sprintf("feed %s is stale: %s was last modified %s ago (max_age %s); run make feeds to refresh it",
				f.Name, f.Path, age.Truncate(time.Minute), f.MaxAge))
		}
	}
	for _, m := range msgs {
		d.log.WriteEvent(logging.EventRecord{Time: now, Event: logging.EventWarning, OK: true, Rules: d.eng.Stats().Rules, Path: d.opt.rules, Message: m})
		if d.dash == nil {
			fmt.Fprintln(d.stderr, "ids: warning:", m)
		}
	}
	d.hmu.Lock()
	d.header.Feeds = status
	d.hmu.Unlock()
}
