package logging

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"

	"github.com/bUrn-1337/intrusion-detection-system/internal/rules"
)

// Writer defaults.
const (
	DefaultBuffer   = 10000
	DefaultMaxSize  = 100 << 20 // 100 MB
	DefaultMaxFiles = 5
)

// WriterConfig configures a Writer. Zero values select the defaults.
type WriterConfig struct {
	Path string
	// MaxSize is the size in bytes a file may reach before it is rotated.
	// A record that would take the file past MaxSize goes into a new file
	// instead (a single record larger than MaxSize gets a file of its own).
	MaxSize int64
	// MaxFiles is how many rotated files (Path.1 ... Path.MaxFiles) are
	// kept besides the current one.
	MaxFiles int
	// Buffer is the capacity of the record channel.
	Buffer int
}

// WriterStats are the Writer's counters.
type WriterStats struct {
	Written   uint64 `json:"written"`   // records written to the file
	Dropped   uint64 `json:"dropped"`   // records refused because the buffer was full (or after Close)
	Errors    uint64 `json:"errors"`    // records lost to write, encode or rotation errors
	Rotations uint64 `json:"rotations"` // completed rotations
}

// Writer writes log records from any number of goroutines to one file. A
// single goroutine owns the file; WriteAlert, WriteStats and WriteEvent
// hand records to it through a buffered channel and never block: when the
// channel is full the record is dropped and counted in Stats().Dropped.
//
// Records are encoded by the writer goroutine, so a caller must not modify
// a record (such as an Alert's Details map) after handing it over.
type Writer struct {
	cfg  WriterConfig
	ch   chan any
	done chan struct{}

	mu     sync.RWMutex // guards closed against sends racing Close
	closed bool

	f    *os.File // owned by the writer goroutine
	size int64
	err  error // first error, returned by Close

	beforeWrite func() // test hook, runs in the writer goroutine

	written, dropped, errs, rotations atomic.Uint64
}

// NewWriter opens (or creates, with mode 0600) cfg.Path for appending and
// starts the writer goroutine.
func NewWriter(cfg WriterConfig) (*Writer, error) {
	return newWriter(cfg, nil)
}

func newWriter(cfg WriterConfig, beforeWrite func()) (*Writer, error) {
	if cfg.Path == "" {
		return nil, errors.New("logging: no log file path")
	}
	if cfg.MaxSize <= 0 {
		cfg.MaxSize = DefaultMaxSize
	}
	if cfg.MaxFiles <= 0 {
		cfg.MaxFiles = DefaultMaxFiles
	}
	if cfg.Buffer <= 0 {
		cfg.Buffer = DefaultBuffer
	}
	w := &Writer{cfg: cfg, ch: make(chan any, cfg.Buffer), done: make(chan struct{}), beforeWrite: beforeWrite}
	if err := w.open(); err != nil {
		return nil, err
	}
	go w.run()
	return w, nil
}

// open opens the current file. An existing file keeps its contents but is
// narrowed to mode 0600, since alerts can reveal internal addresses.
func (w *Writer) open() error {
	f, err := os.OpenFile(w.cfg.Path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("logging: %w", err)
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return fmt.Errorf("logging: %w", err)
	}
	if fi.Mode().Perm() != 0o600 {
		if err := f.Chmod(0o600); err != nil {
			f.Close()
			return fmt.Errorf("logging: %w", err)
		}
	}
	w.f, w.size = f, fi.Size()
	return nil
}

// WriteAlert queues an alert record. It reports whether it was accepted.
func (w *Writer) WriteAlert(a rules.Alert) bool {
	return w.send(alertRecord{Type: TypeAlert, Alert: a})
}

// WriteStats queues a stats record.
func (w *Writer) WriteStats(s StatsRecord) bool {
	s.Type = TypeStats
	return w.send(s)
}

// WriteEvent queues an event record.
func (w *Writer) WriteEvent(e EventRecord) bool {
	e.Type = TypeEvent
	return w.send(e)
}

func (w *Writer) send(rec any) bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if !w.closed {
		select {
		case w.ch <- rec:
			return true
		default:
		}
	}
	w.dropped.Add(1)
	return false
}

// Stats returns the writer's counters. It is safe to call at any time.
func (w *Writer) Stats() WriterStats {
	return WriterStats{Written: w.written.Load(), Dropped: w.dropped.Load(), Errors: w.errs.Load(), Rotations: w.rotations.Load()}
}

// Close stops accepting records, writes every record already accepted,
// fsyncs and closes the file. It returns the first error the writer hit,
// if any. It is safe to call more than once.
func (w *Writer) Close() error {
	w.mu.Lock()
	if !w.closed {
		w.closed = true
		close(w.ch)
	}
	w.mu.Unlock()
	<-w.done
	return w.err
}

func (w *Writer) run() {
	defer close(w.done)
	buf := make([]byte, 0, 1024)
	for rec := range w.ch {
		if w.beforeWrite != nil {
			w.beforeWrite()
		}
		b, err := json.Marshal(rec)
		if err != nil {
			w.fail(fmt.Errorf("logging: encode: %w", err))
			continue
		}
		buf = append(append(buf[:0], b...), '\n')
		w.write(buf)
	}
	if w.f != nil {
		if err := w.f.Sync(); err != nil {
			w.fail(fmt.Errorf("logging: %w", err))
		}
		if err := w.f.Close(); err != nil && w.err == nil {
			w.err = fmt.Errorf("logging: %w", err)
		}
	}
}

func (w *Writer) fail(err error) {
	w.errs.Add(1)
	if w.err == nil {
		w.err = err
	}
}

// write writes one record in one write call, rotating first if the record
// would take the file past MaxSize.
func (w *Writer) write(b []byte) {
	if w.size > 0 && w.size+int64(len(b)) > w.cfg.MaxSize {
		if err := w.rotate(); err != nil {
			w.fail(err)
		}
	}
	if w.f == nil {
		// A failed rotation could not reopen the file; try again.
		if err := w.open(); err != nil {
			w.fail(err)
			return
		}
	}
	n, err := w.f.Write(b)
	w.size += int64(n)
	if err != nil {
		w.fail(fmt.Errorf("logging: %w", err))
		return
	}
	w.written.Add(1)
}

// rotate renames Path.i to Path.i+1 from the oldest down (Path.MaxFiles
// is overwritten, which discards it), renames Path to Path.1, and opens a
// new Path.
func (w *Writer) rotate() error {
	if err := w.f.Sync(); err != nil {
		return fmt.Errorf("logging: rotate: %w", err)
	}
	if err := w.f.Close(); err != nil {
		return fmt.Errorf("logging: rotate: %w", err)
	}
	w.f = nil
	for i := w.cfg.MaxFiles - 1; i >= 1; i-- {
		err := os.Rename(RotatedName(w.cfg.Path, i), RotatedName(w.cfg.Path, i+1))
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("logging: rotate: %w", err)
		}
	}
	if err := os.Rename(w.cfg.Path, RotatedName(w.cfg.Path, 1)); err != nil {
		return fmt.Errorf("logging: rotate: %w", err)
	}
	w.rotations.Add(1)
	return w.open()
}

// RotatedName returns the name of the i-th rotated file of path (1 is the
// newest).
func RotatedName(path string, i int) string {
	return fmt.Sprintf("%s.%d", path, i)
}
