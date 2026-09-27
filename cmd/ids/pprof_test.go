package main

import (
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
)

func TestPprofAddr(t *testing.T) {
	pcap := synFloodPcap(t, 1)
	for _, addr := range []string{"0.0.0.0:6060", ":6060", "localhost:6060", "[::1]:6060", "192.0.2.1:6060", "127.0.0.1", "127.0.0.2:6060"} {
		code, _, stderr := runIDSTest(t, "run", "-r", pcap, "-rules", rulesPath(t), "-log", filepath.Join(t.TempDir(), "x.jsonl"), "-pprof", addr)
		if code != 2 || !strings.Contains(stderr, "must be 127.0.0.1:PORT") {
			t.Errorf("-pprof %s: exit %d, stderr %q", addr, code, stderr)
		}
	}
	code, _, stderr := runIDSTest(t, "run", "-r", pcap, "-rules", rulesPath(t), "-log", filepath.Join(t.TempDir(), "x.jsonl"), "-no-tui", "-pprof", "127.0.0.1:0")
	if code != 0 || !strings.Contains(stderr, "pprof on http://127.0.0.1:") {
		t.Errorf("exit %d, stderr %q", code, stderr)
	}
}

func TestServePprof(t *testing.T) {
	var errOut strings.Builder
	stop, err := servePprof("127.0.0.1:0", &errOut)
	if err != nil {
		t.Fatal(err)
	}
	url := strings.TrimSpace(strings.TrimPrefix(errOut.String(), "ids: pprof on ")) + "goroutine?debug=1"
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.HasPrefix(string(b), "goroutine profile: total ") {
		t.Errorf("GET %s: %.80q", url, b)
	}
	stop()
	if _, err := http.Get(url); err == nil {
		t.Error("server still answering after stop")
	}
}
