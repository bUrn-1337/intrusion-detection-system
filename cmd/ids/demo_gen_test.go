package main

// Demo-capture dumper. Writes the committed pcaps under demo/captures/ by
// reusing the scenario generators in scenario_gen_test.go, so a demo
// capture is byte-for-byte the traffic its scenario already asserts on
// (or, where a snaplen is set, that traffic captured with `tcpdump -s`).
//
// It is not part of the normal suite: it runs only with IDS_GEN_DEMO=1, so
// `go test ./...` and `make scenarios` skip it. Regenerate the captures with
//
//	IDS_GEN_DEMO=1 go test -run '^TestGenerateDemoCaptures$' ./cmd/ids/
//
// demoCaptures is also the source of truth for demo/replay.sh: the ordered
// list of committed captures, the scenario each comes from, and the sid the
// replay must see. Keep the three in sync.

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/bUrn-1337/intrusion-detection-system/internal/testutil/pcapgen"
)

// demoCapture is one committed capture under demo/captures/.
type demoCapture struct {
	File     string // basename written under demo/captures/
	Scenario string // key in scenarioGenerators
	SID      int    // the headline sid the replay must observe
	Kind     string // "alert" or "incident": what the headline record is
	Snap     int    // snaplen in bytes; 0 keeps the whole frame
}

var demoCaptures = []demoCapture{
	{"01-recon-port-scan.pcap", "vertical_syn_scan", 1000401, "alert", 0},
	{"02-recon-host-sweep.pcap", "horizontal_sweep_port22", 1000402, "alert", 0},
	{"03-dos-syn-flood.pcap", "syn_flood_single_source", 1000001, "alert", 0},
	{"04-dos-udp-flood.pcap", "udp_flood_bytes", 1000012, "alert", 0}, // generator sets its own 128-byte snaplen
	{"05-dos-icmp-smurf.pcap", "smurf_victim", 1000022, "alert", 0},
	{"06-dos-land.pcap", "land_attack", 1000003, "alert", 0},
	{"07-dos-ping-of-death.pcap", "ping_of_death", 1000703, "alert", 0},
	{"08-evasion-teardrop.pcap", "teardrop_overlap", 1000701, "alert", 0},
	{"09-spoof-arp-poison.pcap", "arp_flip_flop", 1000802, "alert", 0},
	{"10-dns-zone-transfer.pcap", "dns_axfr", 1000101, "alert", 0},
	{"11-dns-tunnel.pcap", "dns_tunnel_base32", 1000108, "alert", 0},
	{"12-dns-dga-nxdomain.pcap", "dns_nxdomain_dga", 1000110, "alert", 0},
	{"13-dns-amplification.pcap", "dns_amplification_reflection", 1000103, "alert", 256}, // 3 KB responses; the factor comes from the UDP length
	{"14-web-sqli.pcap", "sqli_union", 1000210, "alert", 0},
	{"15-web-xss.pcap", "xss_script", 1000214, "alert", 0},
	{"16-web-path-traversal.pcap", "path_traversal_decoded", 1000217, "alert", 0},
	{"17-web-cmd-injection.pcap", "cmd_injection", 1000219, "alert", 0},
	{"18-web-log4shell.pcap", "log4shell_plain", 1000221, "alert", 0},
	{"19-web-shellshock.pcap", "shellshock_ua", 1000222, "alert", 0},
	{"20-dos-slowloris.pcap", "slowloris_slow_headers", 1000030, "alert", 0},
	{"21-dos-rudy.pcap", "rudy_slow_body", 1000032, "alert", 0},
	{"22-cred-ftp-bruteforce.pcap", "ftp_bruteforce", 1000301, "alert", 0},
	{"23-c2-beacon.pcap", "beacon_fixed_60s", 1001101, "alert", 0},
	{"24-ti-ip-feed.pcap", "ip_feed_hit_dst", 1001001, "alert", 0},
	{"25-ti-domain-feed.pcap", "domain_feed_dns", 1001002, "alert", 0},
	{"26-ti-ja3-feed.pcap", "ja3_feed_hit", 1001003, "alert", 0},
	{"27-anomaly-baseline-fanout.pcap", "baseline_host_fanout", 1001201, "alert", 0},
	{"28-spoof-ttl-anomaly.pcap", "ttl_spoofed_source", 1000601, "alert", 0},
	{"29-incident-kill-chain.pcap", "kill_chain_full", 1001301, "incident", 0},
	{"30-incident-callback.pcap", "callback_after_exploit", 1001303, "incident", 0},
}

func TestGenerateDemoCaptures(t *testing.T) {
	if os.Getenv("IDS_GEN_DEMO") == "" {
		t.Skip("set IDS_GEN_DEMO=1 to (re)generate demo/captures/*.pcap")
	}
	outDir, err := filepath.Abs("../../demo/captures")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, d := range demoCaptures {
		if seen[d.File] {
			t.Fatalf("duplicate demo capture file %q", d.File)
		}
		seen[d.File] = true
		gen, ok := scenarioGenerators[d.Scenario]
		if !ok {
			t.Fatalf("demo capture %s: no generator for scenario %q", d.File, d.Scenario)
		}
		path := filepath.Join(outDir, d.File)
		w := pcapgen.Create(t, path)
		if d.Snap > 0 {
			w.Snap = d.Snap
		}
		gen(w)
		w.Close()
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatalf("%s: %v", d.File, err)
		}
		if fi.Size() >= 1<<20 {
			t.Errorf("%s is %d bytes, must stay under 1 MiB", d.File, fi.Size())
		}
		t.Logf("wrote %s (%d bytes) from %s", d.File, fi.Size(), d.Scenario)
	}
}
