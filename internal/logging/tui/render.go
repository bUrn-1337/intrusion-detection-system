// Package tui is the IDS dashboard. Rendering (Model -> text of each
// panel) is kept apart from the live Dashboard so it can be tested on a
// tcell SimulationScreen with a fixed Model.
package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"github.com/bUrn-1337/intrusion-detection-system/internal/logging"
	"github.com/bUrn-1337/intrusion-detection-system/internal/rules"
)

// Header is the dashboard header's data.
type Header struct {
	Source  string // "interface eth0" or "file x.pcap"
	Started time.Time
	Rules   int
	// Reload describes the last reload; empty if there has been none.
	Reload   string
	ReloadOK bool
	ReloadAt time.Time
	// Done is set once a pcap file has been read to the end.
	Done bool
	// Feeds are the loaded threat-intel feeds; each is shown with its
	// size and age, red once older than its max age.
	Feeds []FeedStatus
	// Baseline is the state of the first detect:baseline rule; nil if
	// there is none.
	Baseline *rules.BaselineStatus
}

// FeedStatus is a feed's header entry.
type FeedStatus struct {
	Name    string
	Entries int
	ModTime time.Time
	MaxAge  time.Duration // 0: never stale
}

// Health is capture, reassembly and logging health.
type Health struct {
	Captured      uint64
	KernelDropped uint64
	QueueDropped  uint64
	QueueDepth    int
	LogDropped    uint64 // log records dropped by the log writer
	FeedDropped   uint64 // alerts the dashboard feed dropped
	// TCP reassembly (stream.Stats).
	StreamFlows     int64  // flows tracked now
	StreamBuffered  int64  // bytes buffered now
	StreamEvictions uint64 // flows dropped at the memory cap
	StreamGaps      uint64
	StreamDesyncs   uint64
	StreamOverlaps  uint64 // overlap conflicts
}

// Model is everything the dashboard shows.
type Model struct {
	Now    time.Time
	Header Header
	Health Health
	Snap   logging.Snapshot
	Paused bool
	Feed   []rules.Alert // oldest first
	// ShowIncidents switches the bottom panel from the raw alert feed to
	// the full incident list (key i).
	ShowIncidents bool
}

// View holds the dashboard's panels.
type View struct {
	Root                                              *tview.Flex
	header, traffic, health, proto, talkers, alerting *tview.TextView
	incidents, alerts                                 *tview.TextView
}

// IncidentRows is how many incidents the top panel lists.
const IncidentRows = 5

func panel(title string) *tview.TextView {
	t := tview.NewTextView().SetDynamicColors(true).SetWrap(false)
	t.SetBorder(true).SetTitle(" " + title + " ").SetTitleAlign(tview.AlignLeft)
	return t
}

// NewView builds the panel layout.
func NewView() *View {
	v := &View{
		header:    panel("IDS"),
		incidents: panel("Incidents"),
		traffic:   panel("Traffic"),
		health:    panel("Capture health"),
		proto:     panel("Protocols"),
		talkers:   panel("Top talkers (60s)"),
		alerting:  panel("Top alerting sources (60s)"),
		alerts:    panel("Recent alerts"),
	}
	v.alerts.SetScrollable(true)
	row1 := tview.NewFlex().
		AddItem(v.traffic, 0, 1, false).
		AddItem(v.health, 0, 1, false).
		AddItem(v.proto, 0, 1, false)
	row2 := tview.NewFlex().
		AddItem(v.talkers, 0, 3, false).
		AddItem(v.alerting, 0, 2, false)
	v.Root = tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(v.header, 5, 0, false).
		AddItem(v.incidents, IncidentRows+4, 0, false).
		AddItem(row1, 12, 0, false).
		AddItem(row2, 13, 0, false).
		AddItem(v.alerts, 0, 1, false)
	return v
}

// Render sets every panel from m.
func (v *View) Render(m *Model) {
	v.header.SetText(RenderHeader(m))
	v.traffic.SetText(RenderTraffic(m))
	v.health.SetText(RenderHealth(m))
	v.proto.SetText(RenderProtocols(m))
	v.talkers.SetText(RenderTalkers(m))
	v.alerting.SetText(RenderAlerting(m))
	v.incidents.SetTitle(fmt.Sprintf(" Incidents (%d active) ", len(m.Snap.Incidents)))
	v.incidents.SetText(RenderIncidents(m, IncidentRows))
	if m.ShowIncidents {
		v.alerts.SetTitle(" All incidents [i: raw alerts] ")
		v.alerts.SetText(RenderIncidents(m, 0))
		v.alerts.ScrollToBeginning()
		return
	}
	title := " Recent alerts [i: incidents] "
	if m.Paused {
		title = " Recent alerts [PAUSED - p to resume] "
	}
	v.alerts.SetTitle(title)
	v.alerts.SetText(RenderAlerts(m))
	v.alerts.ScrollToEnd()
}

// incidentClock is the time incidents age by: the wall clock live, the
// newest alert time when reading a pcap file (whose alerts carry packet
// times).
func incidentClock(m *Model) time.Time {
	if strings.HasPrefix(m.Header.Source, "file ") && !m.Snap.AlertClock.IsZero() {
		return m.Snap.AlertClock
	}
	return m.Now
}

// RenderIncidents renders the active incidents, most severe first, then
// by score: severity, score, kind, entity, the stage chain and the age
// since the incident was created. limit > 0 lists at most limit and says
// how many more there are; limit 0 lists all, with their ids.
func RenderIncidents(m *Model, limit int) string {
	in := m.Snap.Incidents
	if len(in) == 0 {
		return " [green]no active incidents[-]"
	}
	now := incidentClock(m)
	var b strings.Builder
	// Cells are cut and padded before escaping: tview.Escape lengthens
	// text like "[high]", which would throw off %-Ns padding.
	fmt.Fprintf(&b, " [::b]%s %6s  %s %s %s %5s[::-]", cell("SEV", 10), "SCORE", cell("KIND", 16), cell("ENTITY", 34), cell("STAGES", 42), "AGE")
	if limit == 0 {
		b.WriteString("[::b]  " + cell("ID", 20) + " ALERTS UPDATES[::-]")
	}
	for i, x := range in {
		if limit > 0 && i == limit {
			fmt.Fprintf(&b, "\n [gray]+%d more (i: all incidents)[-]", len(in)-limit)
			break
		}
		fmt.Fprintf(&b, "\n [%s]%s %6d  %s %s %s %5s", SeverityColor(x.Severity), cell("["+x.Severity+"]", 10), x.Score,
			cell(x.Kind, 16), cell(x.Entity, 34), cell(x.Chain, 42), formatAge(max(now.Sub(x.FirstSeen), 0)))
		if limit == 0 {
			fmt.Fprintf(&b, "  %s %6d %7d", cell(x.ID, 20), x.Contributing, x.Updates)
		}
		b.WriteString("[-]")
	}
	return b.String()
}

// cell cuts s to w runes (ending in "…" when cut), pads it to w and
// escapes it for tview.
func cell(s string, w int) string {
	r := []rune(s)
	if len(r) > w {
		r = append(r[:w-1], '…')
	}
	return tview.Escape(string(r) + strings.Repeat(" ", w-len(r)))
}

// RenderHeader renders the header panel.
func RenderHeader(m *Model) string {
	h := m.Header
	up := time.Duration(0)
	if !h.Started.IsZero() && m.Now.After(h.Started) {
		up = m.Now.Sub(h.Started).Truncate(time.Second)
	}
	src := tview.Escape(h.Source)
	if h.Done {
		src += " [yellow](end of file)[-]"
	}
	reload := "none"
	if h.Reload != "" {
		color := "green"
		if !h.ReloadOK {
			color = "red"
		}
		reload = fmt.Sprintf("[%s]%s[-] at %s", color, tview.Escape(h.Reload), h.ReloadAt.Format("15:04:05"))
	}
	return fmt.Sprintf(" Source: [::b]%s[::-]   Uptime: %s   Rules loaded: %d   Last reload: %s\n Feeds: %s\n Baseline: %s   [gray]keys: q quit   p pause alerts   i incidents/alerts   r reload rules[-]",
		src, formatUptime(up), h.Rules, reload, renderFeeds(h.Feeds, m.Now), renderBaseline(h.Baseline))
}

// renderBaseline describes the baseline: learning (with progress and the
// packet time learning ends), active, or active with anomalous metrics.
func renderBaseline(b *rules.BaselineStatus) string {
	switch {
	case b == nil:
		return "none"
	case b.Until.IsZero():
		return fmt.Sprintf("[yellow]learning 0/%d (no packets yet)[-]", b.Learn)
	case !b.Active:
		return fmt.Sprintf("[yellow]learning %d/%d until %s[-]", b.Learned, b.Learn, b.Until.Local().Format("15:04:05"))
	case b.Anomalous > 0:
		return fmt.Sprintf("[red]active, %d anomalous[-]", b.Anomalous)
	}
	return "[green]active[-]"
}

func renderFeeds(fs []FeedStatus, now time.Time) string {
	if len(fs) == 0 {
		return "none"
	}
	parts := make([]string, len(fs))
	for i, f := range fs {
		age := max(now.Sub(f.ModTime), 0)
		s := fmt.Sprintf("%s %d (%s)", tview.Escape(f.Name), f.Entries, formatAge(age))
		if f.MaxAge > 0 && age > f.MaxAge {
			s = "[red]" + s + " STALE[-]"
		}
		parts[i] = s
	}
	return strings.Join(parts, "   ")
}

// formatAge is a coarse age: 45s, 12m, 5h, 9d.
func formatAge(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	}
	return fmt.Sprintf("%dd", int(d.Hours()/24))
}

func formatUptime(d time.Duration) string {
	h := int(d.Hours())
	return fmt.Sprintf("%02d:%02d:%02d", h, int(d.Minutes())%60, int(d.Seconds())%60)
}

// RenderTraffic renders the traffic panel.
func RenderTraffic(m *Model) string {
	s := m.Snap
	return fmt.Sprintf(
		" Packets/s  %10s   avg60 %10s\n Bytes/s    %10s   avg60 %10s\n\n Packets    %10s\n Bytes      %10s\n Alerts     %10s",
		Human(s.PPS), Human(s.AvgPPS), HumanBytes(s.BPS), HumanBytes(s.AvgBPS),
		fmt.Sprint(s.Packets), HumanBytes(float64(s.Bytes)), fmt.Sprint(s.Alerts))
}

// RenderHealth renders the capture health panel. A non-zero drop count
// is red: a dropping IDS is blind to what it dropped. Stream evictions
// count as drops: an evicted flow is no longer reassembled.
func RenderHealth(m *Model) string {
	h := m.Health
	return fmt.Sprintf(" Captured          %12d\n Kernel drops      %s\n Queue drops       %s\n Queue depth       %12d\n Log records drop  %s\n Alert feed drops  %s\n"+
		" Streams %8d  buf %10s\n Stream evictions  %s\n Gaps/desyncs/ovl  %12s",
		h.Captured, drop(h.KernelDropped), drop(h.QueueDropped), h.QueueDepth, drop(h.LogDropped), drop(h.FeedDropped),
		h.StreamFlows, HumanBytes(float64(h.StreamBuffered)), drop(h.StreamEvictions),
		fmt.Sprintf("%d/%d/%d", h.StreamGaps, h.StreamDesyncs, h.StreamOverlaps))
}

func drop(n uint64) string {
	if n == 0 {
		return fmt.Sprintf("[green]%12d[-]", n)
	}
	return fmt.Sprintf("[red::b]%12d[-::-]", n)
}

// RenderProtocols renders the protocol breakdown.
func RenderProtocols(m *Model) string {
	var b strings.Builder
	b.WriteString(" [::b]L4[::-]\n")
	for _, c := range m.Snap.ByL4 {
		fmt.Fprintf(&b, "  %-8s %10d %5.1f%%\n", tview.Escape(c.Name), c.Packets, pct(c.Packets, m.Snap.Packets))
	}
	b.WriteString(" [::b]App[::-]\n")
	for _, c := range m.Snap.ByApp {
		fmt.Fprintf(&b, "  %-8s %10d %5.1f%%\n", tview.Escape(c.Name), c.Packets, pct(c.Packets, m.Snap.Packets))
	}
	return strings.TrimSuffix(b.String(), "\n")
}

func pct(n, total uint64) float64 {
	if total == 0 {
		return 0
	}
	return 100 * float64(n) / float64(total)
}

// RenderTalkers renders the top talkers by packets and by bytes side by
// side.
func RenderTalkers(m *Model) string {
	var b strings.Builder
	fmt.Fprintf(&b, " [::b]%-24s %9s   %-24s %9s[::-]\n", "By packets", "pkts", "By bytes", "bytes")
	n := max(len(m.Snap.TopPackets), len(m.Snap.TopBytes))
	for i := 0; i < n; i++ {
		var l, r string
		if i < len(m.Snap.TopPackets) {
			t := m.Snap.TopPackets[i]
			l = fmt.Sprintf("%-24s %9d", t.IP, t.Packets)
		} else {
			l = strings.Repeat(" ", 34)
		}
		if i < len(m.Snap.TopBytes) {
			t := m.Snap.TopBytes[i]
			r = fmt.Sprintf("%-24s %9s", t.IP, HumanBytes(float64(t.Bytes)))
		}
		fmt.Fprintf(&b, " %s   %s\n", l, r)
	}
	if m.Snap.Untracked > 0 {
		fmt.Fprintf(&b, " [yellow]%d packets from sources over the tracking cap[-]\n", m.Snap.Untracked)
	}
	return strings.TrimSuffix(b.String(), "\n")
}

// RenderAlerting renders the top sources by alert count.
func RenderAlerting(m *Model) string {
	var b strings.Builder
	fmt.Fprintf(&b, " [::b]%-24s %8s[::-]\n", "Source", "alerts")
	for _, t := range m.Snap.TopAlerts {
		fmt.Fprintf(&b, " [red]%-24s[-] %8d\n", t.IP, t.Alerts)
	}
	return strings.TrimSuffix(b.String(), "\n")
}

// SeverityColor is the feed color of a severity.
func SeverityColor(sev string) string {
	switch sev {
	case rules.SeverityCritical:
		return "fuchsia"
	case rules.SeverityHigh:
		return "red"
	case rules.SeverityMedium:
		return "yellow"
	case rules.SeverityLow:
		return "aqua"
	}
	return "white"
}

// RenderAlerts renders the raw alert feed (alerts and summaries, not
// incidents), newest last.
func RenderAlerts(m *Model) string {
	var b strings.Builder
	for _, a := range m.Feed {
		if logging.IsIncident(&a) {
			continue
		}
		if b.Len() > 0 {
			b.WriteByte('\n')
		}
		kind := ""
		if a.Kind == rules.KindSummary {
			kind = " (summary)"
		}
		fmt.Fprintf(&b, "[%s]%s %-8s sid=%d %s %s -> %s count=%d%s[-]",
			SeverityColor(a.Severity), a.Time.Format("15:04:05"), tview.Escape("["+a.Severity+"]"), a.SID,
			tview.Escape(fmt.Sprintf("%q", a.Msg)), endpoint(a.SrcIP, a.SrcPort), endpoint(a.DstIP, a.DstPort), a.Count, kind)
	}
	return b.String()
}

func endpoint(ip string, port uint16) string {
	if port == 0 {
		return ip
	}
	if strings.Contains(ip, ":") {
		return fmt.Sprintf("[%s]:%d", ip, port)
	}
	return fmt.Sprintf("%s:%d", ip, port)
}

// Human formats a rate with k/M/G suffixes.
func Human(v float64) string {
	switch {
	case v >= 1e9:
		return fmt.Sprintf("%.2fG", v/1e9)
	case v >= 1e6:
		return fmt.Sprintf("%.2fM", v/1e6)
	case v >= 1e3:
		return fmt.Sprintf("%.2fk", v/1e3)
	}
	return fmt.Sprintf("%.0f", v)
}

// HumanBytes formats a byte count with binary units.
func HumanBytes(v float64) string {
	switch {
	case v >= 1<<30:
		return fmt.Sprintf("%.2f GiB", v/(1<<30))
	case v >= 1<<20:
		return fmt.Sprintf("%.2f MiB", v/(1<<20))
	case v >= 1<<10:
		return fmt.Sprintf("%.2f KiB", v/(1<<10))
	}
	return fmt.Sprintf("%.0f B", v)
}

// Draw renders m into screen at its full size, without an Application.
// Tests use it with a tcell SimulationScreen.
func Draw(screen tcell.Screen, m *Model) {
	v := NewView()
	v.Render(m)
	w, h := screen.Size()
	v.Root.SetRect(0, 0, w, h)
	screen.Clear()
	v.Root.Draw(screen)
	screen.Show()
}
