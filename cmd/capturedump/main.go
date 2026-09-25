// Command capturedump runs the Module 1 capturer on its own and prints one
// line per frame: capture timestamp, captureLen/wireLen, and the first 16
// bytes in hex. On Ctrl-C (or EOF for a file) it prints the final Stats.
// It is for manual testing only.
//
// Usage:
//
//	capturedump -i eth0 [-f "tcp port 80"]
//	capturedump -r trace.pcap
package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/bUrn-1337/intrusion-detection-system/internal/capture"
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
		head := p.RawData[:min(16, len(p.RawData))]
		fmt.Printf("%s  %d/%d  %s\n",
			p.Timestamp.Format(time.RFC3339Nano), p.CaptureLen, p.WireLen, hex.EncodeToString(head))
	}

	s := c.Stats()
	fmt.Fprintf(os.Stderr, "captured=%d kernel_dropped=%d queue_dropped=%d queue_depth=%d\n",
		s.Captured, s.KernelDropped, s.QueueDropped, s.QueueDepth)
	return c.Err()
}
