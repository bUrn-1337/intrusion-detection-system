#!/usr/bin/env bash
# soak.sh - long-running stability soak for the IDS detection pipeline.
#
# Replays the committed demo captures in a continuous loop through one
# long-lived `ids` process and samples RSS, throughput, drops and table
# evictions. It reads packets from a FIFO, so it needs no network and no
# capabilities - a plain `go build` binary works. This stresses the pipeline
# (parse -> detect -> reassemble -> correlate -> log), not the live capture
# layer, and is meant to surface memory growth or unbounded state over time.
#
#   scripts/soak.sh                    # 3600s soak into ./soak-out/
#   SECS=120 scripts/soak.sh out/      # short soak into out/
#   IDS=bin/ids SECS=600 scripts/soak.sh
#
# Env: SECS (default 3600), SAMPLE seconds between samples (default 15),
#      IDS (binary; default: build a scratch one).
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH= cd -- "$here/.." && pwd)
cd "$root"

SECS=${SECS:-3600}
SAMPLE=${SAMPLE:-15}
OUT=${1:-soak-out}
mkdir -p "$OUT"

IDS=${IDS:-}
if [ -z "$IDS" ]; then
	IDS="$OUT/ids"
	echo "building scratch binary $IDS ..."
	go build -o "$IDS" ./cmd/ids
fi

caps=$(ls demo/captures/*.pcap 2>/dev/null | wc -l)
[ "$caps" -gt 0 ] || { echo "no demo/captures/*.pcap found" >&2; exit 1; }

fifo="$OUT/soak.fifo"; rm -f "$fifo"; mkfifo "$fifo"
log="$OUT/soak.jsonl"; rss="$OUT/rss.csv"; : > "$log"
echo "elapsed_s,rss_mb" > "$rss"

# Feeder: one global header, then every capture's packet records on repeat.
FEED_SECS=$SECS FIFO="$fifo" python3 - <<'PY' &
import os, glob, time
secs = float(os.environ["FEED_SECS"]); fifo = os.environ["FIFO"]
files = sorted(glob.glob("demo/captures/*.pcap"))
gh = open(files[0], "rb").read(24)               # all captures share this header
bodies = [open(f, "rb").read()[24:] for f in files]
end = time.time() + secs
with open(fifo, "wb") as f:
    f.write(gh); f.flush()
    try:
        while time.time() < end:
            for b in bodies:
                f.write(b)
            f.flush()
    except BrokenPipeError:
        pass
PY
feeder=$!

# Reader: one long-lived pipeline, stats every SAMPLE seconds.
"$IDS" run -r "$fifo" -rules rules.conf -no-tui -log "$log" \
	-stats-interval "${SAMPLE}s" >"$OUT/ids.out" 2>&1 &
ids=$!

echo "soak: pid $ids, ${SECS}s, sampling every ${SAMPLE}s -> $rss"
start=$(date +%s)
while kill -0 "$ids" 2>/dev/null; do
	now=$(date +%s); el=$((now - start))
	if [ -r "/proc/$ids/status" ]; then
		kb=$(awk '/^VmRSS:/{print $2}' "/proc/$ids/status" 2>/dev/null || echo)
		[ -n "${kb:-}" ] && printf '%s,%s\n' "$el" "$(awk "BEGIN{printf \"%.1f\", $kb/1024}")" >> "$rss"
	fi
	[ "$el" -ge "$((SECS + SAMPLE))" ] && break
	sleep "$SAMPLE"
done
wait "$feeder" 2>/dev/null || true
wait "$ids" 2>/dev/null || true
rm -f "$fifo"

# Summary from the last stats record + the RSS series.
python3 - "$log" "$rss" <<'PY'
import sys, json
log, rss = sys.argv[1], sys.argv[2]
stats = [json.loads(l) for l in open(log) if '"type":"stats"' in l]
peak = 0.0; first = last = None
rows = [r.strip().split(",") for r in open(rss)][1:]
vals = [(float(a), float(b)) for a, b in rows if b]
if vals:
    peak = max(v for _, v in vals); first = vals[0][1]; last = vals[-1][1]
print("==== soak summary ====")
if stats:
    s = stats[-1]; e = s["engine"]; c = s["capture"]
    up = s["uptime_seconds"]; pk = e["packets"]
    ev = sum(t["evictions"] for t in e["tables"].values())
    print(f"uptime            : {up:,.0f} s")
    print(f"packets processed : {pk:,}")
    print(f"mean throughput   : {pk/up:,.0f} pkt/s" if up else "")
    print(f"captured / dropped: {c['captured']:,} / kernel {c['kernel_dropped']:,}, queue {c['queue_dropped']:,}")
    print(f"alerts / incidents: {e['alerts']:,} / {e['incidents']:,}")
    print(f"table evictions   : {ev:,}  (LRU caps working; not a leak)")
    print(f"stats samples      : {len(stats)}")
if vals:
    # Sample 0 is pre-load; use the second sample as the post-warmup baseline.
    warm = vals[1] if len(vals) > 1 else vals[0]
    print(f"RSS first / peak / last : {first:.1f} / {peak:.1f} / {last:.1f} MB")
    print(f"RSS post-warmup baseline: {warm[1]:.1f} MB at {warm[0]:,.0f} s")
    print(f"RSS growth warmup->last : {last-warm[1]:+.1f} MB over {vals[-1][0]-warm[0]:,.0f} s "
          f"(leak check)")
PY
