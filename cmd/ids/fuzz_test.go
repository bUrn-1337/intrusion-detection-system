package main

import (
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gopacket/gopacket/pcapgo"

	"github.com/bUrn-1337/intrusion-detection-system/internal/packet"
	"github.com/bUrn-1337/intrusion-detection-system/internal/parser/app"
	"github.com/bUrn-1337/intrusion-detection-system/internal/parser/lower"
	"github.com/bUrn-1337/intrusion-detection-system/internal/parser/upper"
	"github.com/bUrn-1337/intrusion-detection-system/internal/rules"
	"github.com/bUrn-1337/intrusion-detection-system/internal/stream"
	"github.com/bUrn-1337/intrusion-detection-system/internal/testutil/pcapgen"
)

// Fuzz input format: a sequence of records, each a 2-byte big-endian
// header followed by a frame. The header's low 11 bits are the frame
// length (cut to what is left); the top 5 bits advance the packet clock by
// that many 100ms steps, so inputs can cross dedup and flood windows.
const fuzzLenMask = 1<<11 - 1

func encodeFuzzFrames(frames [][]byte, step uint16) []byte {
	var out []byte
	for _, f := range frames {
		if len(f) > fuzzLenMask {
			f = f[:fuzzLenMask]
		}
		out = binary.BigEndian.AppendUint16(out, step<<11|uint16(len(f)))
		out = append(out, f...)
	}
	return out
}

// FuzzPipeline feeds arbitrary frames through lower -> upper -> app ->
// engine with the default rules, as the ids pipeline does. It checks that
// nothing panics and that every alert is well formed.
func FuzzPipeline(f *testing.F) {
	rs, err := rules.Load("../../rules.conf")
	if err != nil {
		f.Fatal(err)
	}
	// Seeds: every scenario's traffic, a few frames per seed.
	for name, gen := range scenarioGenerators {
		path := filepath.Join(f.TempDir(), name+".pcap")
		w := pcapgen.Create(f, path)
		gen(w)
		w.Close()
		frames := readFrames(f, path)
		for i := 0; i < len(frames); i += 16 {
			f.Add(encodeFuzzFrames(frames[i:min(i+16, len(frames))], 0))
			if i > 64 {
				break
			}
		}
	}
	f.Add([]byte{})
	f.Add([]byte{0xff, 0xff})

	sids := make(map[int]bool)
	for _, r := range rs.Rules() {
		sids[r.SID] = true
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		e := rules.NewEngine(rs, rules.EngineConfig{MaxKeys: 64})
		now := pcapgen.T0
		check := func(as []rules.Alert) {
			for _, a := range as {
				if !sids[a.SID] || a.Count < 1 || (a.Kind != rules.KindAlert && a.Kind != rules.KindSummary) {
					t.Fatalf("bad alert %+v", a)
				}
			}
		}
		for len(data) >= 2 {
			h := binary.BigEndian.Uint16(data)
			n := min(int(h&fuzzLenMask), len(data)-2)
			frame := append([]byte(nil), data[2:2+n]...)
			data = data[2+n:]
			now = now.Add(time.Duration(h>>11) * 100 * time.Millisecond)

			p := packet.NewParsedPacket(now, uint32(len(frame)), uint32(len(frame)))
			p.RawData = frame
			lower.Parse(p)
			upper.Parse(p)
			app.Parse(p)
			check(e.Process(p))
		}
		check(e.Flush())
	})
}

// streamScenarios are the scenarios whose traffic exercises reassembly;
// FuzzStream seeds with whole conversations from them.
var streamScenarios = []string{
	"http_request_split_3_segments", "http_out_of_order", "http_pipelined",
	"http_midstream_pickup", "dns_axfr_split_prefix", "dns_tcp_split_response",
	"tls_clienthello_split", "tcp_seq_wraparound", "tcp_retransmission_identical",
	"tcp_overlap_conflict", "oversize_headers", "slowloris_slow_headers",
	"rudy_slow_body", "slow_read_zero_window", "ftp_bruteforce", "dns_axfr",
	"http_basic_auth", "benign_mixed", "ids_started_mid_connection",
}

// FuzzStream runs the pipeline with the stream stage, as ids run does
// (lower, upper, stream, app, engine), with small memory caps so that
// eviction and per-flow drops happen. It checks that the stage never
// panics, keeps its memory under the cap, and only hands reassembled
// data to Module 4 for a direction it is reassembling.
//
//	go test -run '^$' -fuzz '^FuzzStream$' -fuzztime 2m ./cmd/ids/
func FuzzStream(f *testing.F) {
	rs, err := rules.Load("../../rules.conf")
	if err != nil {
		f.Fatal(err)
	}
	for _, name := range streamScenarios {
		path := filepath.Join(f.TempDir(), name+".pcap")
		w := pcapgen.Create(f, path)
		scenarioGenerators[name](w)
		w.Close()
		frames := readFrames(f, path)
		for i := 0; i < len(frames) && i < 256; i += 64 {
			f.Add(encodeFuzzFrames(frames[i:min(i+64, len(frames))], 0))
		}
	}
	sids := make(map[int]bool)
	for _, r := range rs.Rules() {
		sids[r.SID] = true
	}
	cfg := stream.Config{MaxBytes: 192 << 10, MaxOOO: 4, MaxFlowBytes: 1}
	f.Fuzz(func(t *testing.T, data []byte) {
		e := rules.NewEngine(rs, rules.EngineConfig{MaxKeys: 64})
		sr := stream.New(cfg)
		// The packet's own flow may exceed the cap: its buffers and its
		// overhead (under 1 KiB).
		limit := int64(cfg.MaxBytes + 2*stream.MaxDNSMessage + 1<<10)
		now := pcapgen.T0
		check := func(as []rules.Alert) {
			for _, a := range as {
				if !sids[a.SID] || a.Count < 1 || (a.Kind != rules.KindAlert && a.Kind != rules.KindSummary) {
					t.Fatalf("bad alert %+v", a)
				}
			}
		}
		for len(data) >= 2 {
			h := binary.BigEndian.Uint16(data)
			n := min(int(h&fuzzLenMask), len(data)-2)
			frame := append([]byte(nil), data[2:2+n]...)
			data = data[2+n:]
			now = now.Add(time.Duration(h>>11) * 100 * time.Millisecond)

			p := packet.NewParsedPacket(now, uint32(len(frame)), uint32(len(frame)))
			p.RawData = frame
			lower.Parse(p)
			upper.Parse(p)
			sr.Process(p)
			if p.AppData != nil && p.StreamProto == "" {
				t.Fatalf("AppData without StreamProto: %q", p.AppData)
			}
			if p.StreamProto != "" && p.FlowID == 0 {
				t.Fatal("StreamProto without FlowID")
			}
			st := sr.Stats()
			if st.Charged > limit || st.Buffered < 0 || st.Flows < 0 {
				t.Fatalf("stats out of bounds: %+v", st)
			}
			app.Parse(p)
			check(e.Process(p))
		}
		check(e.Flush())
	})
}

func readFrames(tb testing.TB, path string) [][]byte {
	tb.Helper()
	fh, err := os.Open(path)
	if err != nil {
		tb.Fatal(err)
	}
	defer fh.Close()
	r, err := pcapgo.NewReader(fh)
	if err != nil {
		tb.Fatal(err)
	}
	var out [][]byte
	for {
		b, _, err := r.ReadPacketData()
		if err == io.EOF {
			return out
		}
		if err != nil {
			tb.Fatal(err)
		}
		out = append(out, b)
	}
}
