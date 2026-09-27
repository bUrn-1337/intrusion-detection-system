package main

// TestScenarios runs every directory under testdata/scenarios through the
// real ids pipeline (run -r FILE -no-tui) and compares the logged alerts
// with the directory's expected.json. See docs/SCENARIOS.md.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/bUrn-1337/intrusion-detection-system/internal/testutil/pcapgen"
)

const scenarioDir = "../../testdata/scenarios"

// scenarioSpec is the content of expected.json.
type scenarioSpec struct {
	Description string `json:"description"`
	// Rules is a rules file relative to the scenario directory. Empty
	// means the repo's rules.conf.
	Rules string `json:"rules"`
	// Args are extra "ids run" flags, e.g. ["-whitelist", "10.0.0.0/8"].
	Args []string `json:"args"`
	// Alerts must each match exactly one logged alert record.
	Alerts []expectedAlert `json:"alerts"`
	// AbsentSIDs must not appear in any alert record.
	AbsentSIDs []int `json:"absent_sids"`
	// AllowExtra accepts alert records that no entry in Alerts matches.
	// Without it, any such record fails the scenario.
	AllowExtra bool `json:"allow_extra"`
	// LogMustNotContain lists strings (credentials) that must not appear
	// anywhere in the log or on stdout.
	LogMustNotContain []string `json:"log_must_not_contain"`
}

// expectedAlert matches alert records on stable fields only. Empty or
// zero fields match anything.
type expectedAlert struct {
	SID     int               `json:"sid"`
	Kind    string            `json:"kind"` // "alert" or "summary"
	SrcIP   string            `json:"src_ip,omitempty"`
	DstIP   string            `json:"dst_ip,omitempty"`
	SrcPort int               `json:"src_port,omitempty"`
	DstPort int               `json:"dst_port,omitempty"`
	Count   []int             `json:"count,omitempty"`   // [min, max], inclusive
	Details map[string]string `json:"details,omitempty"` // subset of the alert's details
}

// gotAlert is the part of a logged alert record that scenarios may check.
type gotAlert struct {
	SID     int               `json:"sid"`
	Kind    string            `json:"kind"`
	SrcIP   string            `json:"src_ip"`
	DstIP   string            `json:"dst_ip"`
	SrcPort int               `json:"src_port"`
	DstPort int               `json:"dst_port"`
	Count   int               `json:"count"`
	Details map[string]string `json:"details"`
}

func (e expectedAlert) matches(g gotAlert) bool {
	if e.SID != g.SID || e.Kind != g.Kind ||
		(e.SrcIP != "" && e.SrcIP != g.SrcIP) || (e.DstIP != "" && e.DstIP != g.DstIP) ||
		(e.SrcPort != 0 && e.SrcPort != g.SrcPort) || (e.DstPort != 0 && e.DstPort != g.DstPort) {
		return false
	}
	if len(e.Count) == 2 && (g.Count < e.Count[0] || g.Count > e.Count[1]) {
		return false
	}
	for k, v := range e.Details {
		if g.Details[k] != v {
			return false
		}
	}
	return true
}

func (e expectedAlert) String() string {
	s := fmt.Sprintf("sid=%d kind=%s", e.SID, e.Kind)
	if e.SrcIP != "" || e.SrcPort != 0 {
		s += fmt.Sprintf(" src=%s:%d", or(e.SrcIP, "*"), e.SrcPort)
	}
	if e.DstIP != "" || e.DstPort != 0 {
		s += fmt.Sprintf(" dst=%s:%d", or(e.DstIP, "*"), e.DstPort)
	}
	if len(e.Count) == 2 {
		s += fmt.Sprintf(" count=%d..%d", e.Count[0], e.Count[1])
	}
	if len(e.Details) > 0 {
		s += fmt.Sprintf(" details⊇%v", e.Details)
	}
	return s
}

func (g gotAlert) String() string {
	return fmt.Sprintf("sid=%d kind=%s %s:%d -> %s:%d count=%d details=%v",
		g.SID, g.Kind, g.SrcIP, g.SrcPort, g.DstIP, g.DstPort, g.Count, g.Details)
}

func or(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// scenarioGenerators write each scenario's pcap at test time. A scenario
// with a checked-in capture.pcap needs no generator.
var scenarioGenerators = map[string]func(w *pcapgen.Writer){
	"syn_flood_single_source":   genSYNFloodSingleSource,
	"syn_flood_spoofed":         genSYNFloodSpoofed,
	"completed_handshakes_busy": genCompletedHandshakesBusy,
	"whitelisted_flood":         genSYNFloodSingleSource, // same traffic, the attacker is whitelisted
	"dns_axfr":                  genDNSAXFR,
	"dns_malformed_loop":        genDNSMalformedLoop,
	"http_basic_auth":           genHTTPBasicAuth,
	"http_double_encoding":      genHTTPDoubleEncoding,
	"ftp_bruteforce":            genFTPBruteforce,
	"ftp_plaintext_pass":        genFTPPlaintextPass,
	"benign_mixed":              genBenignMixed,
}

func TestScenarios(t *testing.T) {
	entries, err := os.ReadDir(scenarioDir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	for name := range scenarioGenerators {
		if !slices.Contains(names, name) {
			t.Errorf("generator %q has no directory %s/%s", name, scenarioDir, name)
		}
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) { runScenario(t, name) })
	}
}

func runScenario(t *testing.T, name string) {
	dir := filepath.Join(scenarioDir, name)
	raw, err := os.ReadFile(filepath.Join(dir, "expected.json"))
	if err != nil {
		t.Fatal(err)
	}
	var spec scenarioSpec
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&spec); err != nil {
		t.Fatalf("%s/expected.json: %v", dir, err)
	}
	for i, a := range spec.Alerts {
		if a.SID == 0 || (a.Kind != "alert" && a.Kind != "summary") || (a.Count != nil && (len(a.Count) != 2 || a.Count[0] > a.Count[1])) {
			t.Fatalf("%s/expected.json: alerts[%d]: need sid, kind alert|summary, and count as [min, max]", dir, i)
		}
	}

	pcap := filepath.Join(dir, "capture.pcap")
	if _, err := os.Stat(pcap); err != nil {
		gen, ok := scenarioGenerators[name]
		if !ok {
			t.Fatalf("scenario %s has neither capture.pcap nor a generator in scenarioGenerators", name)
		}
		pcap = filepath.Join(t.TempDir(), name+".pcap")
		w := pcapgen.Create(t, pcap)
		gen(w)
		w.Close()
	}
	rulesFile := rulesPath(t)
	if spec.Rules != "" {
		rulesFile = filepath.Join(dir, spec.Rules)
	}

	logPath := filepath.Join(t.TempDir(), "ids.jsonl")
	args := append([]string{"run", "-r", pcap, "-rules", rulesFile, "-log", logPath, "-no-tui"}, spec.Args...)
	code, stdout, stderr := runIDSTest(t, args...)
	if code != 0 {
		t.Fatalf("ids %s: exit %d\nstderr: %s", strings.Join(args, " "), code, stderr)
	}
	logBytes, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range spec.LogMustNotContain {
		if strings.Contains(string(logBytes), s) || strings.Contains(stdout, s) || strings.Contains(stderr, s) {
			t.Errorf("output contains %q, which must never be logged", s)
		}
	}

	var got []gotAlert
	for _, r := range readLog(t, logPath) {
		if r.Type != "alert" {
			continue
		}
		var g gotAlert
		if err := json.Unmarshal(r.Raw, &g); err != nil {
			t.Fatal(err)
		}
		got = append(got, g)
	}

	var problems []string
	used := make([]bool, len(got))
	for _, e := range spec.Alerts {
		found := false
		for i, g := range got {
			if !used[i] && e.matches(g) {
				used[i], found = true, true
				break
			}
		}
		if !found {
			problems = append(problems, "missing:    "+e.String())
		}
	}
	for i, g := range got {
		if slices.Contains(spec.AbsentSIDs, g.SID) {
			problems = append(problems, "forbidden:  "+g.String()+" (sid is in absent_sids)")
		} else if !used[i] && !spec.AllowExtra {
			problems = append(problems, "unexpected: "+g.String())
		}
	}
	if len(problems) == 0 {
		return
	}
	sort.Strings(problems)
	var b strings.Builder
	fmt.Fprintf(&b, "scenario %s: alerts differ from %s/expected.json\n", name, dir)
	for _, p := range problems {
		b.WriteString("  " + p + "\n")
	}
	b.WriteString("all alerts logged:\n")
	if len(got) == 0 {
		b.WriteString("  (none)\n")
	}
	for _, g := range got {
		b.WriteString("  " + g.String() + "\n")
	}
	t.Error(b.String())
}
