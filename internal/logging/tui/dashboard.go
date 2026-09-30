package tui

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"github.com/bUrn-1337/intrusion-detection-system/internal/logging"
	"github.com/bUrn-1337/intrusion-detection-system/internal/rules"
)

// DefaultFeedBuffer is the capacity of the dashboard's alert channel.
const DefaultFeedBuffer = 1000

// FeedSize is how many alerts the feed keeps.
const FeedSize = logging.DefaultRecentAlerts

// Sources are the dashboard's data sources and actions. The functions are
// called from the UI goroutine and must be safe for that.
type Sources struct {
	Snapshot func() logging.Snapshot
	Header   func() Header
	Health   func() Health // FeedDropped is filled in by the dashboard
	// Reload asks for a rules reload. It must not block; the outcome
	// shows up through Header.
	Reload func()
}

// Dashboard is the live terminal UI. It never blocks the pipeline: alerts
// reach it through SendAlert, which drops (and counts) when its channel is
// full, and everything else is read from snapshots once per second.
type Dashboard struct {
	src     Sources
	app     *tview.Application
	view    *View
	feedCh  chan rules.Alert
	dropped atomic.Uint64

	// Owned by the UI goroutine.
	model   Model
	resumed bool // refill the feed from the snapshot on the next refresh

	refresh  time.Duration
	stopOnce sync.Once
	quit     chan struct{}
}

// New returns a Dashboard. feedBuffer <= 0 selects DefaultFeedBuffer.
func New(src Sources, feedBuffer int) *Dashboard {
	if feedBuffer <= 0 {
		feedBuffer = DefaultFeedBuffer
	}
	d := &Dashboard{
		src:     src,
		app:     tview.NewApplication(),
		view:    NewView(),
		feedCh:  make(chan rules.Alert, feedBuffer),
		refresh: time.Second,
		quit:    make(chan struct{}),
	}
	d.app.SetRoot(d.view.Root, true).SetInputCapture(d.handleKey)
	return d
}

// SendAlert offers an alert to the feed without blocking. It reports
// whether the alert was accepted.
func (d *Dashboard) SendAlert(a rules.Alert) bool {
	select {
	case d.feedCh <- a:
		return true
	default:
		d.dropped.Add(1)
		return false
	}
}

// FeedDropped is the number of alerts SendAlert dropped.
func (d *Dashboard) FeedDropped() uint64 { return d.dropped.Load() }

// Run shows the dashboard on screen (nil: the terminal) until q is
// pressed or Stop is called.
func (d *Dashboard) Run(screen tcell.Screen) error {
	if screen != nil {
		d.app.SetScreen(screen)
	}
	d.update()
	go d.refreshLoop()
	err := d.app.Run()
	d.Stop()
	return err
}

// Stop closes the dashboard; Run returns. It is safe to call from any
// goroutine, more than once.
func (d *Dashboard) Stop() {
	d.stopOnce.Do(func() {
		close(d.quit)
		d.app.Stop()
	})
}

// refreshLoop redraws once per interval. tview's QueueUpdateDraw waits for
// the event loop, so a refresh queued just as the application stops can
// leave this goroutine parked; that only happens at exit.
func (d *Dashboard) refreshLoop() {
	t := time.NewTicker(d.refresh)
	defer t.Stop()
	for {
		select {
		case <-d.quit:
			return
		case <-t.C:
		}
		d.app.QueueUpdateDraw(d.update)
	}
}

// update refreshes the model from the sources and re-renders. It runs on
// the UI goroutine.
func (d *Dashboard) update() {
	m := &d.model
	m.Now = time.Now()
	if d.src.Snapshot != nil {
		m.Snap = d.src.Snapshot()
	}
	if d.src.Header != nil {
		m.Header = d.src.Header()
	}
	if d.src.Health != nil {
		m.Health = d.src.Health()
	}
	m.Health.FeedDropped = d.dropped.Load()
	d.drainFeed()
	d.view.Render(m)
}

// drainFeed moves queued alerts into the feed. While paused the channel
// is still drained, so it never fills up, but the feed stays frozen; on
// resume the feed is rebuilt from the aggregator's recent alerts.
func (d *Dashboard) drainFeed() {
	m := &d.model
	if d.resumed {
		d.resumed = false
		m.Feed = append(m.Feed[:0], m.Snap.RecentAlerts...)
	}
	for {
		select {
		case a := <-d.feedCh:
			if !m.Paused {
				m.Feed = append(m.Feed, a)
			}
		default:
			if n := len(m.Feed) - FeedSize; n > 0 {
				m.Feed = append(m.Feed[:0], m.Feed[n:]...)
			}
			return
		}
	}
}

func (d *Dashboard) handleKey(ev *tcell.EventKey) *tcell.EventKey {
	if ev.Key() != tcell.KeyRune {
		if ev.Key() == tcell.KeyCtrlC {
			d.Stop()
			return nil
		}
		return ev
	}
	switch ev.Rune() {
	case 'q', 'Q':
		d.Stop()
	case 'p', 'P':
		d.model.Paused = !d.model.Paused
		if !d.model.Paused {
			d.resumed = true
		}
		d.update()
	case 'i', 'I':
		d.model.ShowIncidents = !d.model.ShowIncidents
		d.update()
	case 'r', 'R':
		if d.src.Reload != nil {
			d.src.Reload()
		}
	default:
		return ev
	}
	return nil
}
