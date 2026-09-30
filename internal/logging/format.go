package logging

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/bUrn-1337/intrusion-detection-system/internal/rules"
)

// Printer writes query results as an aligned table or as raw JSON Lines.
type Printer struct {
	w      io.Writer
	json   bool
	header bool
}

// NewPrinter returns a Printer writing to w. With asJSON it writes each
// record's line exactly as it is in the log.
func NewPrinter(w io.Writer, asJSON bool) *Printer {
	return &Printer{w: w, json: asJSON}
}

const tableFormat = "%-24s %-7s %-8s %-8s %-5s %-21s %-21s %6s  %s\n"

// Print writes one record.
func (p *Printer) Print(r Record) error {
	if p.json {
		_, err := fmt.Fprintf(p.w, "%s\n", r.Raw)
		return err
	}
	if !p.header {
		p.header = true
		if _, err := fmt.Fprintf(p.w, tableFormat, "TIME", "KIND", "SEV", "SID", "PROTO", "SOURCE", "DESTINATION", "COUNT", "MESSAGE"); err != nil {
			return err
		}
	}
	ts := formatTime(r.Time)
	var err error
	switch {
	case r.Alert != nil:
		a := r.Alert
		_, err = fmt.Fprintf(p.w, tableFormat, ts, a.Kind, a.Severity, fmt.Sprint(a.SID), a.Proto,
			hostPort(a.SrcIP, a.SrcPort), hostPort(a.DstIP, a.DstPort), fmt.Sprint(a.Count), clean(a.Msg))
	case r.Stats != nil:
		_, err = fmt.Fprintf(p.w, tableFormat, ts, "stats", "-", "-", "-", "-", "-", "-", statsSummary(r.Stats))
	case r.Event != nil:
		_, err = fmt.Fprintf(p.w, tableFormat, ts, "event", "-", "-", "-", "-", "-", "-", eventSummary(r.Event))
	}
	return err
}

func formatTime(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.000Z")
}

func hostPort(ip string, port uint16) string {
	if port == 0 {
		return ip
	}
	if strings.Contains(ip, ":") {
		return fmt.Sprintf("[%s]:%d", ip, port)
	}
	return fmt.Sprintf("%s:%d", ip, port)
}

func statsSummary(s *StatsRecord) string {
	return fmt.Sprintf("%s uptime=%.0fs packets=%d bytes=%d captured=%d kernel_dropped=%d queue_dropped=%d alerts=%d summaries=%d incidents=%d log_dropped=%d",
		s.Reason, s.Uptime, s.Traffic.Packets, s.Traffic.Bytes, s.Capture.Captured, s.Capture.KernelDropped,
		s.Capture.QueueDropped, s.Engine.Alerts, s.Engine.Summaries, s.Engine.Incidents, s.Log.Dropped)
}

func eventSummary(e *EventRecord) string {
	if e.Event != EventReload {
		return fmt.Sprintf("%s: %s", e.Event, clean(e.Message))
	}
	if e.OK {
		return fmt.Sprintf("%s ok rules=%d", e.Event, e.Rules)
	}
	first, _, more := strings.Cut(e.Error, "\n")
	s := fmt.Sprintf("%s FAILED (kept %d rules): %s", e.Event, e.Rules, clean(first))
	if more {
		s += fmt.Sprintf(" (+%d more)", strings.Count(e.Error, "\n"))
	}
	return s
}

// clean replaces control characters so a log value cannot move the
// terminal cursor or forge table rows.
func clean(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return '?'
		}
		return r
	}, s)
}

// FormatAlert formats an alert or summary as the one-line form printed by
// capturedump -rules and ids -no-tui:
//
//	ALERT [high] sid=N "msg" TCP src:port -> dst:port count=1 time=... k=v ...
//	SUMMARY [high] sid=N "msg" TCP src:port -> dst:port count=N first=... last=... k=v ...
//	INCIDENT [critical] sid=N "msg" IP attacker -> victim count=1 time=... chain=... k=v ...
//	INCIDENT_UPDATE [critical] ... (the same, when an incident grows)
func FormatAlert(a rules.Alert) string {
	var b strings.Builder
	kind := strings.ToUpper(a.Kind)
	if kind == "" {
		kind = "ALERT"
	}
	fmt.Fprintf(&b, "%s [%s] sid=%d %q %s %s -> %s count=%d", kind, a.Severity, a.SID, a.Msg, a.Proto,
		alertEndpoint(a.SrcIP, a.SrcPort, a.Proto), alertEndpoint(a.DstIP, a.DstPort, a.Proto), a.Count)
	if a.Kind == rules.KindSummary {
		fmt.Fprintf(&b, " first=%s last=%s", a.FirstSeen.Format(time.RFC3339Nano), a.LastSeen.Format(time.RFC3339Nano))
	} else {
		fmt.Fprintf(&b, " time=%s", a.Time.Format(time.RFC3339Nano))
	}
	keys := make([]string, 0, len(a.Details))
	for k := range a.Details {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, " %s=%s", k, a.Details[k])
	}
	return b.String()
}

func alertEndpoint(ip string, port uint16, proto string) string {
	if proto != "TCP" && proto != "UDP" {
		return ip
	}
	if strings.Contains(ip, ":") {
		return fmt.Sprintf("[%s]:%d", ip, port)
	}
	return fmt.Sprintf("%s:%d", ip, port)
}
