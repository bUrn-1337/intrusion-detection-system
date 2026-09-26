package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/bUrn-1337/intrusion-detection-system/internal/logging"
)

func runQuery(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("ids query", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		f      logging.Filter
		path   string
		follow bool
		asJSON bool
		poll   time.Duration
	)
	fs.StringVar(&path, "log", defaultLog, "log file to read (rotated files path.1, path.2, ... are read too)")
	fs.StringVar(&f.MinSeverity, "severity", "", "minimum severity: low, medium, high or critical")
	fs.DurationVar(&f.Since, "since", 0, "only records from the last `DURATION` (e.g. 15m, 2h)")
	fs.Func("from", "only records at or after `TIME` (RFC 3339, or 2006-01-02[ 15:04[:05]] local)", func(v string) (err error) {
		f.From, err = parseTime(v)
		return err
	})
	fs.Func("to", "only records at or before `TIME`", func(v string) (err error) {
		f.To, err = parseTime(v)
		return err
	})
	fs.Func("src", "alert source `IP or CIDR`", func(v string) (err error) {
		f.Src, err = logging.ParsePrefix(v)
		return err
	})
	fs.Func("dst", "alert destination `IP or CIDR`", func(v string) (err error) {
		f.Dst, err = logging.ParsePrefix(v)
		return err
	})
	fs.IntVar(&f.SID, "sid", 0, "rule SID")
	fs.StringVar(&f.Category, "category", "", "rule category (case-insensitive)")
	fs.StringVar(&f.Kind, "kind", "", "alert kind: alert or summary")
	fs.StringVar(&f.Type, "type", logging.TypeAlert, "record type: alert, stats, event or all")
	fs.BoolVar(&follow, "follow", false, "keep printing new matching records, like tail -f (Ctrl-C stops)")
	fs.BoolVar(&asJSON, "json", false, "print raw JSON Lines instead of a table")
	fs.DurationVar(&poll, "poll", logging.DefaultPoll, "with -follow, how often to check for new records")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "ids query: unexpected arguments %q\n", fs.Args())
		return 2
	}
	if err := f.Validate(); err != nil {
		fmt.Fprintln(stderr, "ids query:", err)
		return 2
	}
	if f.Since > 0 && !f.From.IsZero() {
		fmt.Fprintln(stderr, "ids query: use -since or -from, not both")
		return 2
	}

	p := logging.NewPrinter(stdout, asJSON)
	var (
		st  logging.QueryStats
		err error
	)
	if follow {
		st, err = logging.Follow(ctx, path, f, p.Print, poll)
	} else {
		st, err = logging.Query(path, f, p.Print)
	}
	if err != nil {
		fmt.Fprintln(stderr, "ids query:", err)
		return 1
	}
	if !asJSON {
		fmt.Fprintf(stderr, "%d matching record(s)", st.Matched)
		if st.Invalid > 0 {
			fmt.Fprintf(stderr, ", %d invalid line(s) skipped", st.Invalid)
		}
		fmt.Fprintln(stderr)
	} else if st.Invalid > 0 {
		fmt.Fprintf(stderr, "ids query: %d invalid line(s) skipped\n", st.Invalid)
	}
	return 0
}

func parseTime(v string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339Nano, v); err == nil {
		return t, nil
	}
	for _, layout := range []string{"2006-01-02 15:04:05", "2006-01-02T15:04:05", "2006-01-02 15:04", "2006-01-02"} {
		if t, err := time.ParseInLocation(layout, v, time.Local); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("bad time %q (want RFC 3339 or 2006-01-02[ 15:04[:05]])", v)
}
