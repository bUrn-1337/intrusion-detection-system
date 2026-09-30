// Command capturedump runs the Module 1 capturer and the Module 2, 3 and 4
// parsers and prints one decoded line per frame: capture timestamp, wire
// length (and captured length if truncated), Ethernet addresses, then the
// IPv4, IPv6 or ARP summary or the EtherType, then the TCP, UDP or ICMP
// summary (with [bad-l4csum] when the transport checksum is wrong), then the
// DNS, HTTP, FTP or TLS summary with any malformed or suspicious reasons,
// then any parse errors. On Ctrl-C (or EOF for a file) it prints the final Stats. It
// is for manual testing only.
//
// With -rules, every frame also goes through the Module 5 rule engine and
// its alerts are printed as ALERT and SUMMARY lines after the frame that
// caused them; -alerts-only prints just those. SIGHUP reloads the rules
// file (a file with errors is reported and the old rules are kept). At
// exit the engine is flushed, so pending dedup summaries are printed.
//
// With -w FILE, every captured frame is also written to a pcap file
// (Ethernet, the capture snaplen, microsecond timestamps), for recording
// traffic to replay later with ids run -r.
//
// Usage:
//
//	capturedump -i eth0 [-f "tcp port 80"] [-rules rules.conf [-alerts-only] [-whitelist 10.0.0.0/8,192.168.1.5]]
//	capturedump -r trace.pcap
//	capturedump -i eth0 -w trace.pcap > /dev/null
//
// Example output:
//
//	2026-09-25T10:00:00.123456Z  len=74  02:00:00:00:00:0a -> 02:00:00:00:00:0b  IPv4 10.0.0.1 -> 10.0.0.2 proto=6 ttl=64  TCP 40000 -> 443 [SYN] seq=1000 ack=0 win=64240 len=0
//	2026-09-25T10:00:00.153456Z  len=85  02:00:00:00:00:0a -> 02:00:00:00:00:0b  IPv4 10.0.0.1 -> 10.0.0.2 proto=17 ttl=64  UDP 40000 -> 53 len=51  DNS query google.com A
//	2026-09-25T10:00:00.173456Z  len=98  02:00:00:00:00:0b -> 02:00:00:00:00:0a  IPv4 10.0.0.2 -> 10.0.0.1 proto=1 ttl=64  ICMP Echo Reply id=4 seq=1 len=56
//	2026-09-25T10:00:00.223456Z  len=42  02:00:00:00:00:0a -> ff:ff:ff:ff:ff:ff  ARP request who-has 10.0.0.2 tell 10.0.0.1
//	ALERT [high] sid=1000001 "SYN flood against one destination" TCP 10.0.0.1:40000 -> 10.0.0.2:80 count=1 time=2026-09-25T10:00:03.99Z detector=syn_flood ...
//	SUMMARY [high] sid=1000001 "SYN flood against one destination" TCP 10.0.0.1:40000 -> 10.0.0.2:80 count=401 first=2026-09-25T10:00:03.99Z last=2026-09-25T10:00:07.99Z ...
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"

	"github.com/bUrn-1337/intrusion-detection-system/internal/capture"
	"github.com/bUrn-1337/intrusion-detection-system/internal/logging"
	"github.com/bUrn-1337/intrusion-detection-system/internal/packet"
	"github.com/bUrn-1337/intrusion-detection-system/internal/parser/app"
	"github.com/bUrn-1337/intrusion-detection-system/internal/parser/lower"
	"github.com/bUrn-1337/intrusion-detection-system/internal/parser/upper"
	"github.com/bUrn-1337/intrusion-detection-system/internal/rules"
)

type options struct {
	rules      string
	alertsOnly bool
	whitelist  []netip.Prefix
	write      string
}

func main() {
	cfg := capture.DefaultConfig()
	flag.StringVar(&cfg.Interface, "i", "", "network interface for live capture")
	flag.StringVar(&cfg.PcapFile, "r", "", "pcap file to read")
	flag.StringVar(&cfg.BPFFilter, "f", "", "BPF filter expression")
	flag.IntVar(&cfg.Snaplen, "snaplen", cfg.Snaplen, "max bytes captured per frame (live only)")
	flag.IntVar(&cfg.QueueSize, "queue", cfg.QueueSize, "output queue size")
	flag.BoolVar(&cfg.Promisc, "promisc", cfg.Promisc, "promiscuous mode (live only)")
	var opt options
	flag.StringVar(&opt.rules, "rules", "", "rules file; prints ALERT and SUMMARY lines (SIGHUP reloads it)")
	flag.BoolVar(&opt.alertsOnly, "alerts-only", false, "with -rules, print only alerts, not every frame")
	flag.Func("whitelist", "comma-separated source `CIDR`s or addresses that never alert (with -rules)", func(v string) error {
		wl, err := parseWhitelist(v)
		opt.whitelist = append(opt.whitelist, wl...)
		return err
	})
	flag.StringVar(&opt.write, "w", "", "also write every captured frame to this pcap `file`")
	flag.Parse()
	if opt.rules == "" && (opt.alertsOnly || opt.whitelist != nil) {
		fmt.Fprintln(os.Stderr, "capturedump: -alerts-only and -whitelist need -rules")
		os.Exit(2)
	}

	if err := run(cfg, opt); err != nil {
		fmt.Fprintln(os.Stderr, "capturedump:", err)
		os.Exit(1)
	}
}

func run(cfg capture.Config, opt options) error {
	var e *rules.Engine
	if opt.rules != "" {
		rs, err := rules.Load(opt.rules)
		if err != nil {
			return err
		}
		e = rules.NewEngine(rs, rules.EngineConfig{Whitelist: opt.whitelist})
		fmt.Fprintf(os.Stderr, "loaded %d rules from %s\n", rs.Len(), opt.rules)
	}

	c, err := capture.New(cfg)
	if err != nil {
		return err
	}
	defer c.Close()

	var pw *pcapWriter
	if opt.write != "" {
		if pw, err = createPcap(opt.write, cfg.Snaplen); err != nil {
			return err
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if e != nil {
		hup := make(chan os.Signal, 1)
		signal.Notify(hup, syscall.SIGHUP)
		defer signal.Stop(hup)
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case <-hup:
					if err := e.Reload(opt.rules); err != nil {
						fmt.Fprintf(os.Stderr, "reload failed, keeping the previous %d rules:\n%v\n", e.Stats().Rules, err)
					} else {
						fmt.Fprintf(os.Stderr, "reloaded %d rules from %s\n", e.Stats().Rules, opt.rules)
					}
				}
			}
		}()
	}

	for p := range c.Start(ctx) {
		if pw != nil {
			pw.write(p)
		}
		lower.Parse(p)
		upper.Parse(p)
		app.Parse(p)
		if !opt.alertsOnly {
			fmt.Println(describe(p))
		}
		if e != nil {
			printAlerts(e.Process(p))
		}
	}

	s := c.Stats()
	fmt.Fprintf(os.Stderr, "captured=%d kernel_dropped=%d queue_dropped=%d queue_depth=%d\n",
		s.Captured, s.KernelDropped, s.QueueDropped, s.QueueDepth)
	if pw != nil {
		if err := pw.close(); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "wrote %d frames to %s\n", pw.n, opt.write)
	}
	if e != nil {
		printAlerts(e.Flush())
		es := e.Stats()
		fmt.Fprintf(os.Stderr, "rules=%d packets=%d alerts=%d summaries=%d suppressed=%d passed=%d whitelisted=%d evictions=%d reloads=%d reload_fails=%d\n",
			es.Rules, es.Packets, es.Alerts, es.Summaries, es.Suppressed, es.Passed, es.Whitelisted, es.Evictions, es.Reloads, es.ReloadFails)
	}
	return c.Err()
}

// pcapWriter writes captured frames to a pcap file. RawData is owned by
// the packet (capture copies each frame), so it can be written as is.
type pcapWriter struct {
	f   *os.File
	buf *bufio.Writer
	w   *pcapgo.Writer
	n   int
	err error
}

func createPcap(path string, snaplen int) (*pcapWriter, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("creating pcap file: %w", err)
	}
	pw := &pcapWriter{f: f, buf: bufio.NewWriterSize(f, 1<<20)}
	pw.w = pcapgo.NewWriter(pw.buf)
	if err := pw.w.WriteFileHeader(uint32(snaplen), layers.LinkTypeEthernet); err != nil {
		f.Close()
		return nil, fmt.Errorf("writing pcap file: %w", err)
	}
	return pw, nil
}

func (pw *pcapWriter) write(p *packet.ParsedPacket) {
	if pw.err != nil {
		return
	}
	ci := gopacket.CaptureInfo{Timestamp: p.Timestamp, CaptureLength: len(p.RawData), Length: int(p.WireLen)}
	if pw.err = pw.w.WritePacket(ci, p.RawData); pw.err == nil {
		pw.n++
	}
}

// close flushes the file and reports the first write error, if any.
func (pw *pcapWriter) close() error {
	err := pw.err
	if ferr := pw.buf.Flush(); err == nil {
		err = ferr
	}
	if cerr := pw.f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("writing pcap file: %w", err)
	}
	return nil
}

// parseWhitelist parses a comma-separated list of CIDR prefixes and
// single addresses.
func parseWhitelist(v string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, item := range strings.Split(v, ",") {
		item = strings.TrimSpace(item)
		if p, err := netip.ParsePrefix(item); err == nil {
			out = append(out, p.Masked())
		} else if a, err := netip.ParseAddr(item); err == nil {
			a = a.Unmap()
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
		} else {
			return nil, fmt.Errorf("bad whitelist entry %q", item)
		}
	}
	return out, nil
}

func printAlerts(as []rules.Alert) {
	for _, a := range as {
		fmt.Println(logging.FormatAlert(a))
	}
}

// describe formats one parsed frame as a single line.
func describe(p *packet.ParsedPacket) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s  len=%d", p.Timestamp.Format(time.RFC3339Nano), p.WireLen)
	if p.CaptureLen < p.WireLen {
		fmt.Fprintf(&b, " cap=%d", p.CaptureLen)
	}
	if p.EthSrc != nil {
		fmt.Fprintf(&b, "  %s -> %s  ", p.EthSrc, p.EthDst)
		b.WriteString(describeL3(p))
		if l4 := describeL4(p); l4 != "" {
			b.WriteString("  " + l4)
		}
		if a := describeApp(p); a != "" {
			b.WriteString("  " + a)
		}
	}
	if p.HasErrors() {
		fmt.Fprintf(&b, "  errors=%q", p.ParseErrors)
	}
	return b.String()
}

func describeL3(p *packet.ParsedPacket) string {
	switch {
	case p.IPVersion == 4 || p.IPVersion == 6:
		ttl := "ttl"
		if p.IPVersion == 6 {
			ttl = "hlim"
		}
		s := fmt.Sprintf("IPv%d %s -> %s proto=%d %s=%d", p.IPVersion, p.IPSrc, p.IPDst, p.IPProto, ttl, p.IPTTL)
		if p.IPFragmented {
			s += " frag"
		}
		if !p.IPChecksumValid {
			s += " bad-csum"
		}
		return s
	case p.ARPOp == packet.ARPRequest:
		return fmt.Sprintf("ARP request who-has %s tell %s", p.ARPTargetIP, p.ARPSenderIP)
	case p.ARPOp == packet.ARPReply:
		return fmt.Sprintf("ARP reply %s is-at %s", p.ARPSenderIP, p.ARPSenderMAC)
	case p.ARPOp != 0:
		return fmt.Sprintf("ARP op=%d %s -> %s", p.ARPOp, p.ARPSenderIP, p.ARPTargetIP)
	case p.EthType < 0x0600:
		return fmt.Sprintf("802.3 len=%d", p.EthType)
	default:
		return fmt.Sprintf("ethertype 0x%04x", p.EthType)
	}
}

// describeL4 summarizes the transport header, or returns "" when there is
// none or it was malformed (the parse errors then explain why).
func describeL4(p *packet.ParsedPacket) string {
	if p.PayloadOffset < 0 {
		return ""
	}
	var s string
	switch p.L4Proto {
	case packet.L4TCP:
		// The payload length on the wire, not just the captured part.
		n := int64(p.L3Offset) + int64(p.IPTotalLen) - int64(p.PayloadOffset)
		s = fmt.Sprintf("TCP %d -> %d [%s] seq=%d ack=%d win=%d len=%d",
			p.SrcPort, p.DstPort, tcpFlags(p.TCPFlags), p.TCPSeq, p.TCPAck, p.TCPWindow, n)
	case packet.L4UDP:
		s = fmt.Sprintf("UDP %d -> %d len=%d", p.SrcPort, p.DstPort, p.UDPLen)
	case packet.L4ICMP:
		s = "ICMP " + upper.ICMPLabel(p.IPVersion, p.ICMPType, p.ICMPCode)
		if p.HasICMPEcho {
			s += fmt.Sprintf(" id=%d seq=%d len=%d", p.ICMPEchoID, p.ICMPEchoSeq, len(p.Payload()))
		}
	default:
		return ""
	}
	if p.L4ChecksumStatus == packet.L4ChecksumInvalid {
		s += " [bad-l4csum]"
	}
	return s
}

func tcpFlags(f packet.TCPFlags) string {
	var names []string
	for _, fl := range []struct {
		set  bool
		name string
	}{{f.SYN, "SYN"}, {f.ACK, "ACK"}, {f.FIN, "FIN"}, {f.RST, "RST"}, {f.PSH, "PSH"}, {f.URG, "URG"}} {
		if fl.set {
			names = append(names, fl.name)
		}
	}
	return strings.Join(names, ",")
}

// describeApp summarizes the application-layer fields and appends any
// malformed or suspicious reasons. It returns "" for AppUnknown payloads
// with no reasons, and for packets app.Parse did not classify.
func describeApp(p *packet.ParsedPacket) string {
	f := p.AppFields
	var s string
	switch p.AppProtocol {
	case packet.AppDNS:
		switch {
		case f["id"] == "":
			s = "DNS"
		case f["is_response"] == "true":
			s = fmt.Sprintf("DNS response id=%s rcode=%s an=%s", f["id"], f["rcode"], f["ancount"])
			if f["qname"] != "" {
				s += " " + f["qname"]
			}
		case f["qname"] != "":
			qtype := f["qtype_name"]
			if qtype == "" {
				qtype = "type " + f["qtype"]
			}
			s = fmt.Sprintf("DNS query %s %s", f["qname"], qtype)
		default:
			s = "DNS query id=" + f["id"]
		}
	case packet.AppHTTP:
		switch {
		case f["status_code"] != "":
			s = "HTTP " + f["status_code"]
		case f["method"] != "":
			s = strings.Join(nonEmpty("HTTP", f["method"], f["host"], f["uri"]), " ")
			if f["auth_basic"] == "true" {
				s += " auth"
			}
		case f["version"] == "2.0":
			s = "HTTP/2 preface"
		default:
			s = "HTTP"
		}
	case packet.AppFTP:
		if f["response_code"] != "" {
			s = "FTP " + f["response_code"]
		} else {
			// PASS arguments are already "<redacted>" in AppFields.
			s = strings.Join(nonEmpty("FTP", f["command"], f["argument"]), " ")
		}
	case packet.AppTLS:
		switch f["sni_status"] {
		case "found":
			s = "TLS SNI " + f["sni"]
		case "truncated":
			s = "TLS SNI truncated"
		case "absent":
			s = "TLS ClientHello without SNI"
		default:
			s = "TLS"
		}
		if h := f["ja3_hash"]; h != "" {
			s += " JA3 " + h
		}
	}
	for _, kind := range []string{packet.ReasonMalformed, packet.ReasonSuspicious} {
		if r := f[kind+"_reason"]; r != "" {
			s += fmt.Sprintf(" [%s: %s]", kind, r)
		}
	}
	return strings.TrimSpace(s)
}

func nonEmpty(ss ...string) []string {
	var out []string
	for _, s := range ss {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}
