// Command capturedump runs the Module 1 capturer and the Module 2 parser and
// prints one decoded line per frame: capture timestamp, wire length (and
// captured length if truncated), Ethernet addresses, then the IPv4, IPv6 or
// ARP summary or the EtherType, then any parse errors. On Ctrl-C (or EOF for
// a file) it prints the final Stats. It is for manual testing only.
//
// Usage:
//
//	capturedump -i eth0 [-f "tcp port 80"]
//	capturedump -r trace.pcap
//
// Example output:
//
//	2026-09-25T10:00:00.123456Z  len=74  02:00:00:00:00:0a -> 02:00:00:00:00:0b  IPv4 10.0.0.1 -> 10.0.0.2 proto=6 ttl=64
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
