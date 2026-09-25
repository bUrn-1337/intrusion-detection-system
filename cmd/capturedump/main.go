// Command capturedump runs the Module 1 capturer and the Module 2 and 3
// parsers and prints one decoded line per frame: capture timestamp, wire
// length (and captured length if truncated), Ethernet addresses, then the
// IPv4, IPv6 or ARP summary or the EtherType, then the TCP, UDP or ICMP
// summary (with [bad-l4csum] when the transport checksum is wrong), then any
// parse errors. On Ctrl-C (or EOF for a file) it prints the final Stats. It
// is for manual testing only.
//
// Usage:
//
//	capturedump -i eth0 [-f "tcp port 80"]
//	capturedump -r trace.pcap
//
// Example output:
//
//	2026-09-25T10:00:00.123456Z  len=74  02:00:00:00:00:0a -> 02:00:00:00:00:0b  IPv4 10.0.0.1 -> 10.0.0.2 proto=6 ttl=64  TCP 40000 -> 443 [SYN] seq=1000 ack=0 win=64240 len=0
//	2026-09-25T10:00:00.173456Z  len=98  02:00:00:00:00:0b -> 02:00:00:00:00:0a  IPv4 10.0.0.2 -> 10.0.0.1 proto=1 ttl=64  ICMP Echo Reply
//	2026-09-25T10:00:00.223456Z  len=42  02:00:00:00:00:0a -> ff:ff:ff:ff:ff:ff  ARP request who-has 10.0.0.2 tell 10.0.0.1
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/bUrn-1337/intrusion-detection-system/internal/capture"
	"github.com/bUrn-1337/intrusion-detection-system/internal/packet"
	"github.com/bUrn-1337/intrusion-detection-system/internal/parser/lower"
	"github.com/bUrn-1337/intrusion-detection-system/internal/parser/upper"
)

func main() {
	cfg := capture.DefaultConfig()
	flag.StringVar(&cfg.Interface, "i", "", "network interface for live capture")
	flag.StringVar(&cfg.PcapFile, "r", "", "pcap file to read")
	flag.StringVar(&cfg.BPFFilter, "f", "", "BPF filter expression")
	flag.IntVar(&cfg.Snaplen, "snaplen", cfg.Snaplen, "max bytes captured per frame (live only)")
	flag.IntVar(&cfg.QueueSize, "queue", cfg.QueueSize, "output queue size")
	flag.BoolVar(&cfg.Promisc, "promisc", cfg.Promisc, "promiscuous mode (live only)")
	flag.Parse()

	if err := run(cfg); err != nil {
		fmt.Fprintln(os.Stderr, "capturedump:", err)
		os.Exit(1)
	}
}

func run(cfg capture.Config) error {
	c, err := capture.New(cfg)
	if err != nil {
		return err
	}
	defer c.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	for p := range c.Start(ctx) {
		lower.Parse(p)
		upper.Parse(p)
		fmt.Println(describe(p))
	}

	s := c.Stats()
	fmt.Fprintf(os.Stderr, "captured=%d kernel_dropped=%d queue_dropped=%d queue_depth=%d\n",
		s.Captured, s.KernelDropped, s.QueueDropped, s.QueueDepth)
	return c.Err()
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
