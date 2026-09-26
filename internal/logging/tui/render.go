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
}

// Health is capture and logging health.
type Health struct {
	Captured      uint64
	KernelDropped uint64
	QueueDropped  uint64
	QueueDepth    int
	LogDropped    uint64 // log records dropped by the log writer
	FeedDropped   uint64 // alerts the dashboard feed dropped
}

// Model is everything the dashboard shows.
type Model struct {
	Now    time.Time
	Header Header
	Health Health
	Snap   logging.Snapshot
	Paused bool
	Feed   []rules.Alert // oldest first
}

// View holds the dashboard's panels.
type View struct {
	Root                                              *tview.Flex
	header, traffic, health, proto, talkers, alerting *tview.TextView
	alerts                                            *tview.TextView
}

func panel(title string) *tview.TextView {
	t := tview.NewTextView().SetDynamicColors(true).SetWrap(false)
	t.SetBorder(true).SetTitle(" " + title + " ").SetTitleAlign(tview.AlignLeft)
	return t
}

// NewView builds the panel layout.
func NewView() *View {
	v := &View{
		header:   panel("IDS"),
		traffic:  panel("Traffic"),
		health:   panel("Capture health"),
		proto:    panel("Protocols"),
		talkers:  panel("Top talkers (60s)"),
		alerting: panel("Top alerting sources (60s)"),
		alerts:   panel("Recent alerts"),
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
		AddItem(v.header, 4, 0, false).
		AddItem(row1, 10, 0, false).
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
	title := " Recent alerts "
	if m.Paused {
		title = " Recent alerts [PAUSED - p to resume] "
	}
	v.alerts.SetTitle(title)
	v.alerts.SetText(RenderAlerts(m))
	v.alerts.ScrollToEnd()
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
	return fmt.Sprintf(" Source: [::b]%s[::-]   Uptime: %s   Rules loaded: %d   Last reload: %s\n [gray]keys: q quit   p pause alerts   r reload rules[-]",
		src, formatUptime(up), h.Rules, reload)
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
// is red: a dropping IDS is blind to what it dropped.
func RenderHealth(m *Model) string {
	h := m.Health
	return fmt.Sprintf(" Captured          %12d\n Kernel drops      %s\n Queue drops       %s\n Queue depth       %12d\n Log records drop  %s\n Alert feed drops  %s",
		h.Captured, drop(h.KernelDropped), drop(h.QueueDropped), h.QueueDepth, drop(h.LogDropped), drop(h.FeedDropped))
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

// RenderAlerts renders the alert feed, newest last.
func RenderAlerts(m *Model) string {
	var b strings.Builder
	for i, a := range m.Feed {
		if i > 0 {
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
