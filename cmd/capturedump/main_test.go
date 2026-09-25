package main

import (
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/bUrn-1337/intrusion-detection-system/internal/packet"
	"github.com/bUrn-1337/intrusion-detection-system/internal/parser/lower"
	"github.com/bUrn-1337/intrusion-detection-system/internal/parser/upper"
)

func TestDescribe(t *testing.T) {
	const ethIPv4 = "02000000000b02000000000a0800"
	tests := []struct {
		name    string
		hexData string
		wireLen uint32
		want    string
	}{
		{
			name: "ipv4 tcp",
			hexData: ethIPv4 + "45000028123400004006" + "549a" + "0a0000010a000002" +
				"04d2005000000000000000005002000000000000",
			want: "len=54  02:00:00:00:00:0a -> 02:00:00:00:00:0b  IPv4 10.0.0.1 -> 10.0.0.2 proto=6 ttl=64  TCP 1234 -> 80 [SYN] seq=0 ack=0 win=0 len=0 [bad-l4csum]",
		},
		{
			name: "ipv4 fragment with bad checksum, truncated capture",
			hexData: ethIPv4 + "45000028123420004006" + "0000" + "0a0000010a000002" +
				"04d2005000000000000000005002000000000000",
			wireLen: 100,
			want:    "len=100 cap=54  02:00:00:00:00:0a -> 02:00:00:00:00:0b  IPv4 10.0.0.1 -> 10.0.0.2 proto=6 ttl=64 frag bad-csum  TCP 1234 -> 80 [SYN] seq=0 ack=0 win=0 len=0",
		},
		{
			name: "ipv4 tcp syn-ack with payload, valid checksum",
			hexData: ethIPv4 + "4500002b123400004006" + "5497" + "0a0000010a000002" +
				"01bb9c40" + "000003e8" + "000007d0" + "5012faf0" + "32c6" + "0000" + "616263",
			want: "len=57  02:00:00:00:00:0a -> 02:00:00:00:00:0b  IPv4 10.0.0.1 -> 10.0.0.2 proto=6 ttl=64  TCP 443 -> 40000 [SYN,ACK] seq=1000 ack=2000 win=64240 len=3",
		},
		{
			name: "ipv4 udp, no checksum",
			hexData: ethIPv4 + "45000021123400004011" + "5496" + "0a0000010a000002" +
				"9c400035000d0000" + "7175657279",
			want: "len=47  02:00:00:00:00:0a -> 02:00:00:00:00:0b  IPv4 10.0.0.1 -> 10.0.0.2 proto=17 ttl=64  UDP 40000 -> 53 len=13",
		},
		{
			name: "ipv4 icmp port unreachable",
			hexData: ethIPv4 + "4500002000000000400" + "1" + "0000" + "0a0000010a000002" +
				"0303fcfc" + "00000000" + "00000000",
			want: "len=46  02:00:00:00:00:0a -> 02:00:00:00:00:0b  IPv4 10.0.0.1 -> 10.0.0.2 proto=1 ttl=64 bad-csum  ICMP Destination Unreachable (port unreachable)",
		},
		{
			name:    "ipv6",
			hexData: "02000000000b02000000000a86dd" + "6000000000003b40" + "20010db8000000000000000000000001" + "20010db8000000000000000000000002",
			want:    "len=54  02:00:00:00:00:0a -> 02:00:00:00:00:0b  IPv6 2001:db8::1 -> 2001:db8::2 proto=59 hlim=64",
		},
		{
			name:    "arp request",
			hexData: "ffffffffffff02000000000a0806" + "0001080006040001" + "02000000000a0a000001" + "0000000000000a000002",
			want:    "len=42  02:00:00:00:00:0a -> ff:ff:ff:ff:ff:ff  ARP request who-has 10.0.0.2 tell 10.0.0.1",
		},
		{
			name:    "arp reply",
			hexData: "02000000000b02000000000a0806" + "0001080006040002" + "02000000000a0a000001" + "02000000000b0a000002",
			want:    "len=42  02:00:00:00:00:0a -> 02:00:00:00:00:0b  ARP reply 10.0.0.1 is-at 02:00:00:00:00:0a",
		},
		{
			name:    "other ethertype",
			hexData: "02000000000b02000000000a88cc0207",
			want:    "len=16  02:00:00:00:00:0a -> 02:00:00:00:00:0b  ethertype 0x88cc",
		},
		{
			name:    "802.3",
			hexData: "02000000000b02000000000a0026424203",
			want:    "len=17  02:00:00:00:00:0a -> 02:00:00:00:00:0b  802.3 len=38",
		},
		{
			name:    "truncated ipv4 shows errors",
			hexData: ethIPv4 + "4500",
			want:    `len=16  02:00:00:00:00:0a -> 02:00:00:00:00:0b  ethertype 0x0800  errors=["ipv4: truncated header: 2 bytes captured, need 20"]`,
		},
		{
			name:    "runt frame",
			hexData: "0200",
			want:    `len=2  errors=["ethernet: frame too short: 2 bytes, need 14"]`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := hex.DecodeString(tt.hexData)
			if err != nil {
				t.Fatal(err)
			}
			wire := tt.wireLen
			if wire == 0 {
				wire = uint32(len(data))
			}
			p := packet.NewParsedPacket(time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC), uint32(len(data)), wire)
			p.RawData = data
			lower.Parse(p)
			upper.Parse(p)

			got := describe(p)
			const ts = "2026-09-25T10:00:00Z  "
			if !strings.HasPrefix(got, ts) {
				t.Fatalf("describe() = %q, want timestamp prefix %q", got, ts)
			}
			if got = strings.TrimPrefix(got, ts); got != tt.want {
				t.Errorf("describe()\n got: %s\nwant: %s", got, tt.want)
			}
		})
	}
}
