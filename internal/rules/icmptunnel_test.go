package rules

import (
	"bytes"
	"math/rand/v2"
	"strings"
	"testing"
	"time"
)

// counting returns n bytes of the Linux/BSD pattern after a timestamp of
// ts bytes (filled with ts bytes that do not count).
func counting(n, ts int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i)
		if i < ts {
			b[i] = 0xa5
		}
	}
	return b
}

func windowsEcho(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = 'a' + byte(i%23)
	}
	return b
}

func TestStandardEcho(t *testing.T) {
	flip := func(b []byte, i int) []byte {
		c := bytes.Clone(b)
		c[i]++
		return c
	}
	shift := func(b []byte) []byte { // every byte one more: the pattern off by one
		c := bytes.Clone(b)
		for i := range c {
			c[i]++
		}
		return c
	}
	// countFrom returns n bytes counting from start at offset ts, after
	// ts timestamp bytes.
	countFrom := func(n, ts int, start byte) []byte {
		b := counting(n, ts)
		for i := ts; i < n; i++ {
			b[i] = start + byte(i-ts)
		}
		return b
	}
	tests := []struct {
		name string
		b    []byte
		want string
	}{
		{"empty", nil, EchoEmpty},
		{"linux 56 (16-byte timestamp)", counting(56, 16), EchoLinux},
		{"bsd 56 (8-byte timestamp)", counting(56, 8), EchoLinux},
		{"no timestamp", counting(56, 0), EchoLinux},
		{"short, no timestamp", counting(5, 0), EchoLinux},
		{"one byte after 16-byte timestamp", counting(17, 16), EchoLinux},
		{"one byte after 8-byte timestamp", counting(9, 8), EchoLinux},
		{"wraps after 0xff", counting(1472, 16), EchoLinux},
		{"only a 16-byte timestamp", counting(16, 16), ""},
		{"only an 8-byte timestamp", counting(8, 8), ""},
		// The timestamp bytes are not checked, so junk up to offset 16
		// followed by the right counting bytes is standard.
		{"12 junk bytes", counting(56, 12), EchoLinux},
		{"counting from 0x09 after 8", countFrom(56, 8, 0x09), ""},
		{"counting from 0x07 after 8", countFrom(56, 8, 0x07), ""},
		{"counting from 0x11 after 16", countFrom(56, 16, 0x11), ""},
		{"counting from 0x0f after 16", countFrom(56, 16, 0x0f), ""},
		{"counting from 0 after 16", countFrom(56, 16, 0), ""},
		{"counting from 0 after 8", countFrom(56, 8, 0), ""},
		{"17 junk bytes", counting(56, 17), ""},
		{"counting off by one", shift(counting(56, 0)), ""},
		{"last byte wrong", flip(counting(56, 16), 55), ""},
		{"first counting byte wrong", flip(counting(56, 16), 16), ""},
		{"byte 8 wrong is a 16-byte timestamp", flip(counting(56, 8), 8), EchoLinux},
		{"windows 32", windowsEcho(32), EchoWindows},
		{"windows 1", windowsEcho(1), EchoWindows},
		{"windows 1472", windowsEcho(1472), EchoWindows},
		{"windows off by one", shift(windowsEcho(32)), ""},
		{"windows 24th byte wrong", flip(windowsEcho(32), 23), ""},
		{"windows last byte wrong", flip(windowsEcho(32), 31), ""},
		{"26-letter alphabet", []byte(strings.Repeat("abcdefghijklmnopqrstuvwxyz", 2)), ""},
		{"zeros", make([]byte, 64), EchoZero},
		{"zeros, one set", flip(make([]byte, 64), 40), ""},
		{"ping -p ff", bytes.Repeat([]byte{0xff}, 56), ""},
		{"text", []byte("GET /secret HTTP/1.1"), ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := standardEcho(tt.b); got != tt.want {
				t.Errorf("standardEcho = %q, want %q", got, tt.want)
			}
		})
	}
}

// refStandardEcho is standardEcho written the other way round: build
// each pattern at len(b) and compare.
func refStandardEcho(b []byte) string {
	n := len(b)
	if n == 0 {
		return EchoEmpty
	}
	for _, ts := range []int{0, 8, 16} {
		if ts > 0 && n <= ts {
			continue
		}
		want := counting(n, 0)
		if bytes.Equal(b[ts:], want[ts:]) {
			return EchoLinux
		}
	}
	if bytes.Equal(b, windowsEcho(n)) {
		return EchoWindows
	}
	if bytes.Equal(b, make([]byte, n)) {
		return EchoZero
	}
	return ""
}

func FuzzStandardEcho(f *testing.F) {
	for _, s := range [][]byte{nil, counting(56, 16), counting(56, 8), counting(17, 16), counting(16, 16), windowsEcho(32), make([]byte, 8), []byte("x")} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if got, want := standardEcho(b), refStandardEcho(b); got != want {
			t.Fatalf("standardEcho(%x) = %q, reference %q", b, got, want)
		}
	})
}

const tunnelRule = `alert icmp any any -> any any (msg:"m"; sid:1; detect:icmp_tunnel; count:10; seconds:60;)`

func tunnelPkt(req bool, client, server string, payload []byte) pkt {
	if req {
		return pkt{proto: "icmp", src: client, dst: server, echoID: 1, echoSeq: 1, payload: string(payload)}
	}
	return pkt{proto: "icmp", src: server, dst: client, icmp: &[2]uint8{0, 0}, echoID: 1, echoSeq: 1, payload: string(payload)}
}

// lowEntropy returns n bytes that are not a standard pattern and have
// little entropy.
func lowEntropy(n int) []byte { return bytes.Repeat([]byte("ab"), n/2+1)[:n] }

func randomBytes(rng *rand.Rand, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(rng.IntN(256))
	}
	return b
}

func TestICMPTunnel(t *testing.T) {
	const client, server = "10.0.0.5", "198.51.100.20"
	rng := rand.New(rand.NewPCG(1, 2))
	// exact64 has 64 distinct values twice each: exactly 6 bits.
	exact64 := make([]byte, 128)
	exact128 := make([]byte, 128)
	for i := range exact64 {
		exact64[i] = byte(i % 64)
		exact128[i] = byte(i + 100)
	}
	sizes := func(k int) func(i int) []byte {
		return func(i int) []byte { return lowEntropy(40 + i%k) }
	}
	same := func(b []byte) func(int) []byte { return func(int) []byte { return b } }
	tests := []struct {
		name    string
		n       int
		payload func(i int) []byte
		gap     time.Duration
		want    int
	}{
		{"three sizes", 10, sizes(3), 0, 9},
		{"three sizes, nine packets", 9, sizes(3), 0, -1},
		{"two sizes", 20, sizes(2), 0, -1},
		{"one size, low entropy", 20, same(lowEntropy(100)), 0, -1},
		{"entropy exactly 6", 20, same(exact64), 0, -1},
		{"entropy 7", 10, same(exact128), 0, 9},
		{"random, one size", 10, func(int) []byte { return randomBytes(rng, 200) }, 0, 9},
		{"too slow", 10, sizes(3), 6667 * time.Millisecond, -1},
		{"just within 60s", 10, sizes(3), 6666 * time.Millisecond, 9},
		{"standard linux", 20, func(i int) []byte { return counting(40+i%5, 16) }, 0, -1},
		{"standard windows", 20, func(i int) []byte { return windowsEcho(32 + i%5) }, 0, -1},
		{"zeros of many sizes", 20, func(i int) []byte { return make([]byte, 8+i) }, 0, -1},
		{"empty", 20, func(int) []byte { return nil }, 0, -1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var pkts []timedPkt
			for i := range tt.n {
				pkts = append(pkts, timedPkt{time.Duration(i) * tt.gap, tunnelPkt(i%2 == 0, client, server, tt.payload(i))})
			}
			if got := firesAt(t, NewEngine(mustParse(t, tunnelRule), EngineConfig{}), pkts, 1); got != tt.want {
				t.Errorf("fired at %d, want %d", got, tt.want)
			}
		})
	}
}

// TestICMPTunnelPairs: requests and replies of one pair add up; other
// pairs do not, and each pair alerts on its own.
func TestICMPTunnelPairs(t *testing.T) {
	var pkts []timedPkt
	for i := range 10 {
		p := lowEntropy(40 + i%3)
		pkts = append(pkts, timedPkt{0, tunnelPkt(i%2 == 0, "10.0.0.5", "198.51.100.20", p)},
			timedPkt{0, tunnelPkt(true, "10.0.0.5", "198.51.100.21", p)},
			// 10.0.0.5 as the server is another pair.
			timedPkt{0, tunnelPkt(i < 5, "198.51.100.22", "10.0.0.5", p)})
	}
	as := sidAlerts(t, NewEngine(mustParse(t, tunnelRule), EngineConfig{}), pkts, 1)
	if len(as) != 3 {
		t.Fatalf("alerts %v", alertLines(as))
	}
	d := as[0].Details
	if d["client"] != "10.0.0.5" || d["server"] != "198.51.100.20" || d["distinct_sizes"] != "3" || d["payloads"] != "10" ||
		d["payload_hex"] != "61626162616261626162616261626162" || d["payload_len"] != "40" || d["avg_entropy"] != "1.00" {
		t.Errorf("details %v", d)
	}
	if d := as[1].Details; d["server"] != "198.51.100.21" {
		t.Errorf("second alert %v", d)
	}
	if d := as[2].Details; d["client"] != "198.51.100.22" || d["server"] != "10.0.0.5" {
		t.Errorf("third alert %v", d)
	}
}
