#!/usr/bin/env bash
# bench.sh - end-to-end throughput benchmark for the IDS pipeline.
#
# Feeds the committed demo captures through one `ids` process a fixed number
# of times (a finite workload), times it, and reports packets/s and peak RSS.
# Reads a FIFO, so no network and no capabilities are needed.
#
#   scripts/bench.sh                 # LOOPS=40 passes of the corpus
#   LOOPS=100 scripts/bench.sh
#   IDS=bin/ids scripts/bench.sh
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH= cd -- "$here/.." && pwd)
cd "$root"

LOOPS=${LOOPS:-40}
OUT=${1:-$(mktemp -d)}
mkdir -p "$OUT"
IDS=${IDS:-}
if [ -z "$IDS" ]; then IDS="$OUT/ids"; go build -o "$IDS" ./cmd/ids; fi

fifo="$OUT/bench.fifo"; rm -f "$fifo"; mkfifo "$fifo"
log="$OUT/bench.jsonl"

FEED_LOOPS=$LOOPS FIFO="$fifo" python3 - <<'PY' &
import os, glob
loops = int(os.environ["FEED_LOOPS"]); fifo = os.environ["FIFO"]
files = sorted(glob.glob("demo/captures/*.pcap"))
gh = open(files[0], "rb").read(24)
bodies = [open(f, "rb").read()[24:] for f in files]
with open(fifo, "wb") as f:
    f.write(gh)
    for _ in range(loops):
        for b in bodies:
            f.write(b)
PY
feeder=$!

t0=$(date +%s.%N)
"$IDS" run -r "$fifo" -rules rules.conf -no-tui -log "$log" -stats-interval 1h >"$OUT/ids.out" 2>&1 &
ids=$!
peak=0
while kill -0 "$ids" 2>/dev/null; do
	kb=$(awk '/^VmRSS:/{print $2}' "/proc/$ids/status" 2>/dev/null || echo 0)
	[ "${kb:-0}" -gt "$peak" ] 2>/dev/null && peak=$kb
	sleep 0.2
done
wait "$feeder" 2>/dev/null || true
wait "$ids" 2>/dev/null || true
t1=$(date +%s.%N)
rm -f "$fifo"

python3 - "$log" "$t0" "$t1" "$peak" "$LOOPS" <<'PY'
import sys, json
log, t0, t1, peak_kb, loops = sys.argv[1], float(sys.argv[2]), float(sys.argv[3]), float(sys.argv[4]), int(sys.argv[5])
s = [json.loads(l) for l in open(log) if '"type":"stats"' in l][-1]
pk = s["engine"]["packets"]; by = s["traffic"]["bytes"]
wall = t1 - t0
print("==== throughput benchmark ====")
print(f"corpus passes     : {loops}")
print(f"packets processed : {pk:,}")
print(f"wall time         : {wall:.2f} s")
print(f"throughput        : {pk/wall:,.0f} pkt/s")
print(f"                    {by/wall/1e6*8:,.0f} Mbit/s ({by/wall/1e6:,.1f} MB/s)")
print(f"peak RSS          : {peak_kb/1024:,.1f} MB")
print(f"alerts / incidents: {s['engine']['alerts']:,} / {s['engine']['incidents']:,}")
PY
