package logging

import (
	"time"

	"github.com/bUrn-1337/intrusion-detection-system/internal/rules"
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
}

// TableStats is rules.TableStats with JSON names.
type TableStats struct {
	Keys      int64  `json:"keys"`
	Evictions uint64 `json:"evictions"`
}

// EngineStatsFrom converts the engine's counters for logging.
func EngineStatsFrom(s rules.EngineStats) EngineStats {
	out := EngineStats{
		Packets: s.Packets, Alerts: s.Alerts, Summaries: s.Summaries, Suppressed: s.Suppressed,
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
	Event string    `json:"event"` // EventReload
	OK    bool      `json:"ok"`
	Rules int       `json:"rules"`           // rules active afterwards
	Path  string    `json:"path,omitempty"`  // the rules file
	Error string    `json:"error,omitempty"` // every error, one per line
}

// EventReload is the event of a rules reload.
const EventReload = "reload"
