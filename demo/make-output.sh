#!/bin/sh
# make-output.sh - regenerate the committed sample outputs under demo/output/
# from the demo captures. These are the figures the report/slides use.
#
# Deterministic outputs (regenerated here):
#   kill-chain-alerts.jsonl   alert records from the kill-chain capture
#   query-examples.txt        several `ids query` views of that log
#
# The dashboard snapshots are captured live and are not regenerated here:
#   dashboard.txt             default view (top Incidents panel + recent alerts)
#   dashboard-incidents.txt   the `i` view (all incidents, with ids)
# Recapture them with a 160x50 terminal:
#   demo/replay.sh --dashboard 29     # then screenshot, or tmux capture-pane -p
#
# IDS is $IDS or bin/ids (run `make build`).
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH= cd -- "$here/.." && pwd)
cd "$root"
IDS=${IDS:-bin/ids}
if [ ! -x "$IDS" ] && ! command -v "$IDS" >/dev/null 2>&1; then
	echo "error: no IDS binary at '$IDS'. Run 'make build' or set IDS=/path/to/ids." >&2
	exit 1
fi

mkdir -p demo/output
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

cap=demo/captures/29-incident-kill-chain.pcap
log=demo/output/kill-chain-alerts.jsonl
"$IDS" run -r "$cap" -rules rules.conf -no-tui -log "$tmp/full.jsonl" >/dev/null 2>&1
# Keep only alert-type records: they carry packet timestamps, so the file is
# byte-stable across runs (event/stats records carry the wall clock).
grep '"type":"alert"' "$tmp/full.jsonl" > "$log"
echo "wrote $log ($(wc -l < "$log") records)"

out=demo/output/query-examples.txt
q() {
	echo '----------------------------------------------------------------------'
	echo "\$ ids query -log $log $*"
	echo '----------------------------------------------------------------------'
	"$IDS" query -log "$log" "$@"
	echo
}
{
	echo "ids query examples"
	echo "=================="
	echo
	echo "All commands read the committed excerpt $log,"
	echo "the alert records from replaying $cap."
	echo "Regenerate this file with demo/make-output.sh."
	echo
	q -kind incident
	q -kind incident_update
	q -severity critical
	q -src 203.0.113.9
	q -category threat-intel
	q -kind incident -json
} > "$out"
echo "wrote $out"
