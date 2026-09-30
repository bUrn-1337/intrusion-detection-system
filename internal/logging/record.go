package logging

import (
	"time"

	"github.com/bUrn-1337/intrusion-detection-system/internal/rules"
	"github.com/bUrn-1337/intrusion-detection-system/internal/stream"
)

// Record types, the "type" field of every log line.
const (
	TypeAlert = "alert"
	TypeStats = "stats"
	TypeEvent = "event"
)

// Reasons for a stats record.
const (
	StatsPeriodic = "periodic"
	StatsShutdown = "shutdown"
)

// alertRecord is an alert as logged: the rules.Alert JSON plus "type".
type alertRecord struct {
	Type string `json:"type"`
	rules.Alert
}

// StatsRecord is a periodic or final statistics record.
type StatsRecord struct {
	Type    string        `json:"type"` // always TypeStats; set by the Writer
	Time    time.Time     `json:"time"`
	Reason  string        `json:"reason"` // StatsPeriodic or StatsShutdown
	Uptime  float64       `json:"uptime_seconds"`
	Source  string        `json:"source"` // "interface eth0" or "file x.pcap"
	Capture CaptureStats  `json:"capture"`
	Engine  EngineStats   `json:"engine"`
	Stream  StreamStats   `json:"stream"`
	Traffic TrafficTotals `json:"traffic"`
	Log     WriterStats   `json:"log"`
}

// CaptureStats mirrors capture.Stats.
type CaptureStats struct {
	Captured      uint64 `json:"captured"`
	KernelDropped uint64 `json:"kernel_dropped"`
	QueueDropped  uint64 `json:"queue_dropped"`
	QueueDepth    int    `json:"queue_depth"`
}

// EngineStats is rules.EngineStats with JSON names.
type EngineStats struct {
	Packets     uint64 `json:"packets"`
	Alerts      uint64 `json:"alerts"`
	Summaries   uint64 `json:"summaries"`
	Incidents   uint64 `json:"incidents"` // incident and incident_update alerts
	Suppressed  uint64 `json:"suppressed"`
	Passed      uint64 `json:"passed"`
	Whitelisted uint64 `json:"whitelisted"`
	Evictions   uint64 `json:"evictions"`
	Rules       int    `json:"rules"`
	Reloads     uint64 `json:"reloads"`
	ReloadFails uint64 `json:"reload_fails"`
	// FragmentsOverLimit counts datagrams with too many fragments to track.
	FragmentsOverLimit uint64                `json:"fragments_over_limit"`
	Tables             map[string]TableStats `json:"tables"`
	Feeds              []FeedStats           `json:"feeds,omitempty"`
}

// FeedStats describes a loaded threat-intel feed. Ages are in seconds of
// wall time.
type FeedStats struct {
	Name     string  `json:"name"`
	Type     string  `json:"type"`
	Path     string  `json:"path"`
	Entries  int     `json:"entries"`
	Rejected int     `json:"rejected"`
	Age      float64 `json:"age_seconds"`
	MaxAge   float64 `json:"max_age_seconds"` // 0: never stale
	Stale    bool    `json:"stale"`
}

// FeedStatsFrom converts the engine's feed list, computing ages at now.
func FeedStatsFrom(fs []rules.FeedStats, now time.Time) []FeedStats {
	var out []FeedStats
	for _, f := range fs {
		age := max(now.Sub(f.ModTime), 0)
		out = append(out, FeedStats{Name: f.Name, Type: f.Type, Path: f.Path, Entries: f.Entries, Rejected: f.Rejected,
			Age: age.Seconds(), MaxAge: f.MaxAge.Seconds(), Stale: f.MaxAge > 0 && age > f.MaxAge})
	}
	return out
}

// StreamStats is stream.Stats with JSON names.
type StreamStats struct {
	Flows            int64  `json:"flows"`
	FlowsTotal       uint64 `json:"flows_total"`
	Closed           uint64 `json:"closed"`
	IdleClosed       uint64 `json:"idle_closed"`
	Evictions        uint64 `json:"evictions"`
	Gaps             uint64 `json:"gaps"`
	Desyncs          uint64 `json:"desyncs"`
	Resyncs          uint64 `json:"resyncs"`
	OverlapConflicts uint64 `json:"overlap_conflicts"`
	OversizeHeaders  uint64 `json:"oversize_headers"`
	OOOOverflows     uint64 `json:"ooo_overflows"`
	CapDrops         uint64 `json:"cap_drops"`
	Messages         uint64 `json:"messages"`
	Buffered         int64  `json:"buffered_bytes"`
	BufferedPeak     int64  `json:"buffered_peak_bytes"`
	Charged          int64  `json:"charged_bytes"`
}

// StreamStatsFrom converts the stream stage's counters for logging.
func StreamStatsFrom(s stream.Stats) StreamStats {
	return StreamStats{
		Flows: s.Flows, FlowsTotal: s.FlowsTotal, Closed: s.Closed, IdleClosed: s.IdleClosed,
		Evictions: s.Evictions, Gaps: s.Gaps, Desyncs: s.Desyncs, Resyncs: s.Resyncs,
		OverlapConflicts: s.OverlapConflicts, OversizeHeaders: s.OversizeHeaders, OOOOverflows: s.OOOOverflows,
		CapDrops: s.CapDrops, Messages: s.Messages, Buffered: s.Buffered, BufferedPeak: s.BufferedPeak, Charged: s.Charged,
	}
}

// TableStats is rules.TableStats with JSON names.
type TableStats struct {
	Keys      int64  `json:"keys"`
	Evictions uint64 `json:"evictions"`
}

// EngineStatsFrom converts the engine's counters for logging.
func EngineStatsFrom(s rules.EngineStats) EngineStats {
	out := EngineStats{
		Packets: s.Packets, Alerts: s.Alerts, Summaries: s.Summaries, Incidents: s.Incidents, Suppressed: s.Suppressed,
		Passed: s.Passed, Whitelisted: s.Whitelisted, Evictions: s.Evictions, Rules: s.Rules,
		Reloads: s.Reloads, ReloadFails: s.ReloadFails, FragmentsOverLimit: s.FragmentsOverLimit, Tables: make(map[string]TableStats, len(s.Tables)),
	}
	for k, v := range s.Tables {
		out.Tables[k] = TableStats{Keys: v.Keys, Evictions: v.Evictions}
	}
	return out
}

// TrafficTotals are packet counts since start.
type TrafficTotals struct {
	Packets uint64            `json:"packets"`
	Bytes   uint64            `json:"bytes"`
	ByL4    map[string]uint64 `json:"by_l4"`
	ByApp   map[string]uint64 `json:"by_app"`
}

// EventRecord records something that happened to the IDS itself.
type EventRecord struct {
	Type  string    `json:"type"` // always TypeEvent; set by the Writer
	Time  time.Time `json:"time"`
	Event string    `json:"event"` // EventReload, EventWarning, ...
	OK    bool      `json:"ok"`
	Rules int       `json:"rules"`           // rules active afterwards
	Path  string    `json:"path,omitempty"`  // the rules file
	Error string    `json:"error,omitempty"` // every error, one per line
	// Message is the text of an event other than a reload.
	Message string `json:"message,omitempty"`
}

// Event names.
const (
	EventReload   = "reload"   // a rules reload, OK or not
	EventWarning  = "warning"  // a problem that did not stop loading: a rejected feed line, a stale feed
	EventBaseline = "baseline" // a baseline started learning or became active
)
