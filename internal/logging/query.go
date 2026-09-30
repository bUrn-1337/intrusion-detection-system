package logging

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/bUrn-1337/intrusion-detection-system/internal/rules"
)

// TypeAll selects records of every type in a Filter.
const TypeAll = "all"

// Record is one decoded log line.
type Record struct {
	Type  string
	Time  time.Time
	Raw   []byte       // the line as written, without the newline
	Alert *rules.Alert // set for TypeAlert
	Stats *StatsRecord // set for TypeStats
	Event *EventRecord // set for TypeEvent
}

// Filter selects log records. Zero fields match everything, except Type,
// which defaults to alert records only.
//
// MinSeverity, Src, Dst, SID, Category and Kind describe alerts. When any
// of them is set, records of other types never match.
type Filter struct {
	Type        string        // TypeAlert (default), TypeStats, TypeEvent or TypeAll
	MinSeverity string        // low, medium, high, critical
	Since       time.Duration // records from the last Since (overrides an earlier From)
	From, To    time.Time     // inclusive time bounds
	Src, Dst    netip.Prefix  // alert source / destination address
	SID         int
	Category    string
	Kind        string // rules.KindAlert, KindSummary, KindIncident or KindIncidentUpdate
}

// Validate checks the filter's enumerated fields.
func (f Filter) Validate() error {
	switch f.Type {
	case "", TypeAlert, TypeStats, TypeEvent, TypeAll:
	default:
		return fmt.Errorf("unknown record type %q (want alert, stats, event or all)", f.Type)
	}
	if f.MinSeverity != "" && severityRank(f.MinSeverity) < 0 {
		return fmt.Errorf("unknown severity %q (want low, medium, high or critical)", f.MinSeverity)
	}
	switch f.Kind {
	case "", rules.KindAlert, rules.KindSummary, rules.KindIncident, rules.KindIncidentUpdate:
	default:
		return fmt.Errorf("unknown kind %q (want alert, summary, incident or incident_update)", f.Kind)
	}
	if f.Since < 0 {
		return errors.New("negative -since")
	}
	return nil
}

func (f Filter) alertOnly() bool {
	return f.MinSeverity != "" || f.Src.IsValid() || f.Dst.IsValid() || f.SID != 0 || f.Category != "" || f.Kind != ""
}

// resolve turns Since into From, relative to now.
func (f Filter) resolve(now time.Time) Filter {
	if f.Since > 0 {
		if from := now.Add(-f.Since); from.After(f.From) {
			f.From = from
		}
	}
	return f
}

// Match reports whether r passes the filter. Since must already have been
// resolved into From (Query and Follow do that).
func (f Filter) Match(r Record) bool {
	want := f.Type
	if want == "" {
		want = TypeAlert
	}
	if want != TypeAll && r.Type != want {
		return false
	}
	if !f.From.IsZero() && r.Time.Before(f.From) {
		return false
	}
	if !f.To.IsZero() && r.Time.After(f.To) {
		return false
	}
	if !f.alertOnly() {
		return true
	}
	a := r.Alert
	if a == nil {
		return false
	}
	if f.MinSeverity != "" && severityRank(a.Severity) < severityRank(f.MinSeverity) {
		return false
	}
	if f.Src.IsValid() && !prefixHas(f.Src, a.SrcIP) {
		return false
	}
	if f.Dst.IsValid() && !prefixHas(f.Dst, a.DstIP) {
		return false
	}
	if f.SID != 0 && a.SID != f.SID {
		return false
	}
	if f.Category != "" && !strings.EqualFold(a.Category, f.Category) {
		return false
	}
	if f.Kind != "" && a.Kind != f.Kind {
		return false
	}
	return true
}

func prefixHas(p netip.Prefix, ip string) bool {
	a, err := netip.ParseAddr(ip)
	return err == nil && p.Contains(a.Unmap())
}

// severityRank orders severities; unknown ones rank -1.
func severityRank(s string) int {
	switch strings.ToLower(s) {
	case rules.SeverityLow:
		return 0
	case rules.SeverityMedium:
		return 1
	case rules.SeverityHigh:
		return 2
	case rules.SeverityCritical:
		return 3
	}
	return -1
}

// ParsePrefix parses an IP address (as a single-address prefix) or a CIDR.
func ParsePrefix(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("bad CIDR %q", s)
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("bad IP address %q", s)
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// ParseRecord decodes one log line (without its newline).
func ParseRecord(line []byte) (Record, error) {
	var probe struct {
		Type string    `json:"type"`
		Time time.Time `json:"time"`
	}
	if err := json.Unmarshal(line, &probe); err != nil {
		return Record{}, err
	}
	r := Record{Type: probe.Type, Time: probe.Time, Raw: line}
	var err error
	switch probe.Type {
	case TypeAlert:
		r.Alert = new(rules.Alert)
		err = json.Unmarshal(line, r.Alert)
	case TypeStats:
		r.Stats = new(StatsRecord)
		err = json.Unmarshal(line, r.Stats)
	case TypeEvent:
		r.Event = new(EventRecord)
		err = json.Unmarshal(line, r.Event)
	default:
		err = fmt.Errorf("unknown record type %q", probe.Type)
	}
	if err != nil {
		return Record{}, err
	}
	return r, nil
}

// QueryStats counts what a query saw.
type QueryStats struct {
	Matched int // records passed to the callback
	Invalid int // lines that could not be decoded
}

// logFile is an open log file. Holding it open pins the file, whatever
// it is renamed to by later rotations.
type logFile struct {
	name string // at the time it was opened
	fh   *os.File
	fi   os.FileInfo
}

func closeAll(files []logFile) {
	for _, f := range files {
		f.fh.Close()
	}
}

// statLog lists the identities of the rotated files, newest (path.1)
// first, and of the current file (nil if missing). It steps over one
// missing index, which a rotation in progress leaves while it shifts
// files up.
func statLog(path string) (rotated []os.FileInfo, current os.FileInfo) {
	misses := 0
	for i := 1; misses < 2; i++ {
		fi, err := os.Stat(RotatedName(path, i))
		if err != nil {
			misses++
			continue
		}
		misses = 0
		rotated = append(rotated, fi)
	}
	current, _ = os.Stat(path)
	return rotated, current
}

func sameList(a, b []os.FileInfo) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !os.SameFile(a[i], b[i]) {
			return false
		}
	}
	return true
}

func sameOrBothNil(a, b os.FileInfo) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return os.SameFile(a, b)
}

// openLog opens the log's files: the rotated ones oldest first, then the
// current one (nil if it does not exist). A rotation while the files are
// being opened would rename them under us, so it lists, opens, and lists
// again, and retries until nothing moved.
func openLog(path string) (rotated []logFile, current *logFile, err error) {
	for attempt := 0; ; attempt++ {
		before, curBefore := statLog(path)
		rotated, current, err = openListed(path, before, curBefore)
		if err != nil {
			return nil, nil, err
		}
		after, curAfter := statLog(path)
		stable := sameList(before, after) && sameOrBothNil(curBefore, curAfter)
		if stable || attempt >= 100 {
			return rotated, current, nil
		}
		closeAll(rotated)
		if current != nil {
			current.fh.Close()
		}
		time.Sleep(time.Millisecond)
	}
}

// openListed opens the files statLog listed, oldest first, checking each
// is still the file listed. A mismatch or a vanished file just leaves the
// file out; openLog's second listing then sees the change and retries.
func openListed(path string, rotated []os.FileInfo, cur os.FileInfo) ([]logFile, *logFile, error) {
	open := func(want os.FileInfo) (*logFile, error) {
		for i := 1; ; i++ {
			name := RotatedName(path, i)
			if i > len(rotated)+1 {
				name = path
			}
			fi, err := os.Stat(name)
			if err == nil && os.SameFile(fi, want) {
				fh, err := os.Open(name)
				if err != nil {
					if errors.Is(err, os.ErrNotExist) {
						return nil, nil
					}
					return nil, err
				}
				ofi, err := fh.Stat()
				if err != nil || !os.SameFile(ofi, want) {
					fh.Close()
					return nil, err
				}
				return &logFile{name: name, fh: fh, fi: ofi}, nil
			}
			if name == path {
				return nil, nil
			}
		}
	}
	var out []logFile
	for i := len(rotated) - 1; i >= 0; i-- {
		f, err := open(rotated[i])
		if err != nil {
			closeAll(out)
			return nil, nil, err
		}
		if f != nil {
			out = append(out, *f)
		}
	}
	if cur == nil {
		return out, nil, nil
	}
	f, err := open(cur)
	if err != nil {
		closeAll(out)
		return nil, nil, err
	}
	return out, f, nil
}

// LogFiles returns the names of the log's files oldest first: the rotated
// files (path.N ... path.1) that exist, then path itself if it exists.
func LogFiles(path string) []string {
	rotated, current, err := openLog(path)
	if err != nil {
		return nil
	}
	defer closeAll(rotated)
	var names []string
	for _, f := range rotated {
		names = append(names, f.name)
	}
	if current != nil {
		current.fh.Close()
		names = append(names, current.name)
	}
	return names
}

// Query reads the log at path and its rotated files, oldest first, and
// calls fn for every record that matches f. A trailing line without a
// newline in the current file (a record being written) is skipped
// silently; any other line that does not decode is skipped and counted. An
// error from fn stops the query and is returned.
func Query(path string, f Filter, fn func(Record) error) (QueryStats, error) {
	if err := f.Validate(); err != nil {
		return QueryStats{}, err
	}
	f = f.resolve(time.Now())
	rotated, current, err := openLog(path)
	if err != nil {
		return QueryStats{}, err
	}
	defer closeAll(rotated)
	if current != nil {
		defer current.fh.Close()
	}
	if len(rotated) == 0 && current == nil {
		return QueryStats{}, fmt.Errorf("no log file %s", path)
	}
	var st QueryStats
	for _, lf := range rotated {
		if err := readComplete(lf.fh, f, fn, &st); err != nil {
			return st, err
		}
	}
	if current != nil {
		if _, _, err := scan(bufio.NewReader(current.fh), f, fn, &st); err != nil {
			return st, err
		}
	}
	return st, nil
}

// readComplete reads a file that is no longer written to: a partial line
// at its end is a damaged record and is counted as invalid.
func readComplete(r io.Reader, f Filter, fn func(Record) error, st *QueryStats) error {
	_, partial, err := scan(bufio.NewReader(r), f, fn, st)
	if len(partial) > 0 {
		st.Invalid++
	}
	return err
}

// scan passes every complete line of r through f to fn. It returns the
// number of bytes consumed by complete lines and the trailing partial line,
// if any.
func scan(r *bufio.Reader, f Filter, fn func(Record) error, st *QueryStats) (int64, []byte, error) {
	var n int64
	for {
		line, err := r.ReadBytes('\n')
		if err == io.EOF {
			return n, line, nil
		}
		if err != nil {
			return n, nil, err
		}
		n += int64(len(line))
		if err := handleLine(line[:len(line)-1], f, fn, st); err != nil {
			return n, nil, err
		}
	}
}

func handleLine(line []byte, f Filter, fn func(Record) error, st *QueryStats) error {
	line = bytes.TrimSuffix(line, []byte{'\r'})
	if len(bytes.TrimSpace(line)) == 0 {
		return nil
	}
	rec, err := ParseRecord(line)
	if err != nil {
		st.Invalid++
		return nil
	}
	if !f.Match(rec) {
		return nil
	}
	st.Matched++
	return fn(rec)
}

// DefaultPoll is how often Follow checks the log for new data.
const DefaultPoll = 250 * time.Millisecond

// Follow is Query followed by tail -f: after passing the existing records
// to fn it keeps passing new matching records until ctx is done. It
// survives rotation (including several rotations between polls) and
// truncation, and waits for the file if it does not exist yet. It returns
// nil when ctx is cancelled.
func Follow(ctx context.Context, path string, f Filter, fn func(Record) error, poll time.Duration) (QueryStats, error) {
	if err := f.Validate(); err != nil {
		return QueryStats{}, err
	}
	if poll <= 0 {
		poll = DefaultPoll
	}
	fl := &follower{path: path, f: f.resolve(time.Now()), fn: fn}
	defer fl.close()

	// History: the rotated files in full, then the current file up to its
	// last complete line.
	if err := fl.catchUp(nil); err != nil {
		return fl.st, err
	}
	t := time.NewTicker(poll)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return fl.st, nil
		case <-t.C:
		}
		if err := fl.poll(); err != nil {
			return fl.st, err
		}
	}
}

type follower struct {
	path string
	f    Filter
	fn   func(Record) error
	st   QueryStats

	cur     *logFile // the file being followed; nil while path does not exist
	off     int64    // bytes consumed from cur by complete lines
	partial []byte   // an incomplete trailing line, re-read next time
}

func (fl *follower) close() {
	if fl.cur != nil {
		fl.cur.fh.Close()
		fl.cur = nil
	}
}

// catchUp opens the log, reads every rotated file newer than done (all of
// them if done is nil or no longer exists), and starts following the
// current file from its beginning.
func (fl *follower) catchUp(done os.FileInfo) error {
	rotated, current, err := openLog(fl.path)
	if err != nil {
		return err
	}
	defer closeAll(rotated)
	start := 0
	if done != nil {
		for i, lf := range rotated {
			if os.SameFile(lf.fi, done) {
				start = i + 1
			}
		}
	}
	for _, lf := range rotated[start:] {
		if err := readComplete(lf.fh, fl.f, fl.fn, &fl.st); err != nil {
			if current != nil {
				current.fh.Close()
			}
			return err
		}
	}
	fl.cur, fl.off, fl.partial = current, 0, nil
	return fl.readMore()
}

// readMore reads cur from the last complete line to its current end.
func (fl *follower) readMore() error {
	if fl.cur == nil {
		return nil
	}
	if _, err := fl.cur.fh.Seek(fl.off, io.SeekStart); err != nil {
		return err
	}
	n, partial, err := scan(bufio.NewReader(fl.cur.fh), fl.f, fl.fn, &fl.st)
	fl.off += n
	fl.partial = partial
	return err
}

func (fl *follower) poll() error {
	if fl.cur == nil {
		return fl.catchUp(nil)
	}
	// New data in the file we hold, including the last records written
	// before a rotation renamed it.
	if err := fl.readMore(); err != nil {
		return err
	}
	fi, err := os.Stat(fl.path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err == nil && os.SameFile(fi, fl.cur.fi) {
		if fi.Size() < fl.off {
			// Truncated: start over.
			fl.off, fl.partial = 0, nil
			return fl.readMore()
		}
		return nil
	}

	// Rotated (or removed). The file we hold is complete now: read what
	// was written to it since the readMore above. A partial line left in
	// it is a damaged record. Then catch up on the rotated files newer
	// than ours and follow the new current file.
	if err := fl.readMore(); err != nil {
		return err
	}
	if len(fl.partial) > 0 {
		fl.st.Invalid++
	}
	done := fl.cur.fi
	fl.close()
	return fl.catchUp(done)
}
