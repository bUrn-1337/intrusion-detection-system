// Command ids is the network intrusion detection system. It wires the
// capture, parsing, rule and logging modules together.
//
// Usage:
//
//	ids [run] (-i IFACE | -r FILE) [-f BPF] [-rules rules.conf] [-whitelist CIDR[,CIDR]]
//	          [-log ids-alerts.jsonl] [-log-max-size 100M] [-log-max-files 5] [-no-tui]
//	ids query [-log ids-alerts.jsonl] [-severity LEVEL] [-since DUR | -from T -to T]
//	          [-src IP|CIDR] [-dst IP|CIDR] [-sid N] [-category C] [-kind alert|summary]
//	          [-type alert|stats|event|all] [-follow] [-json]
//
// ids run shows a terminal dashboard (keys: q quit, p pause the alert feed,
// r reload rules) unless -no-tui is given or stdout is not a terminal, in
// which case every alert is printed as one line, as capturedump prints it.
// SIGHUP reloads the rules. SIGINT, SIGTERM and q shut down gracefully:
// capture stops, queued packets are processed, pending summaries are
// flushed, a final stats record is logged, and ids exits 0.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

// run dispatches to a subcommand and returns the exit code.
func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	cmd := "run"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	switch cmd {
	case "run":
		return runIDS(ctx, args, stdout, stderr)
	case "query":
		return runQuery(ctx, args, stdout, stderr)
	case "help":
		fmt.Fprintln(stdout, "usage: ids [run] [flags]   (ids run -h for flags)\n       ids query [flags]   (ids query -h for flags)")
		return 0
	}
	fmt.Fprintf(stderr, "ids: unknown subcommand %q (want run or query)\n", cmd)
	return 2
}
