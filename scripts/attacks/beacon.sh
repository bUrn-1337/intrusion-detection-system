#!/usr/bin/env bash
# beacon.sh - periodic C2 callback (Python HTTP client).
# Needs: python3.
# Triggers: sid 1001101 (periodic beacon: regular same-size requests to one host).
# Sends a small GET at a fixed interval with low jitter, the pattern the
# beacon detector keys on.
. "$(cd "$(dirname "$0")" && pwd)/_lib.sh"

usage() { cat <<U
Usage: $PROG --i-have-authorization -t TARGET [-p PORT] [-i INTERVAL] [-c COUNT] [-j JITTER]
  -p PORT      C2 port (default 8080)
  -i INTERVAL  seconds between callbacks (default 60)
  -c COUNT     number of callbacks (default 15)
  -j JITTER    +/- fraction of interval, 0..0.5 (default 0.05)
U
}

TARGET=""; PORT=8080; INTERVAL=60; COUNT=15; JITTER=0.05
while [ $# -gt 0 ]; do
  case $1 in
    --i-have-authorization) AUTHORIZED=1 ;;
    -t|--target) TARGET=${2:?}; shift ;;
    -p|--port) PORT=${2:?}; shift ;;
    -i|--interval) INTERVAL=${2:?}; shift ;;
    -c|--count) COUNT=${2:?}; shift ;;
    -j|--jitter) JITTER=${2:?}; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1 (see --help)" ;;
  esac
  shift
done

need_tool python3
authorize "$TARGET"
export TARGET PORT INTERVAL COUNT JITTER
exec python3 - <<'PY'
import os, time, random, urllib.request
t = os.environ["TARGET"]; p = int(os.environ["PORT"])
interval = float(os.environ["INTERVAL"]); count = int(os.environ["COUNT"])
jitter = min(max(float(os.environ["JITTER"]), 0.0), 0.5)
url = f"http://{t}:{p}/status"
print(f"beacon: {count} callbacks to {url} every ~{interval:g}s (jitter {jitter:g})")
for i in range(count):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "beacon/1.0"})
        urllib.request.urlopen(req, timeout=5).read(64)
    except Exception:
        pass
    if i < count - 1:
        d = interval * (1 + random.uniform(-jitter, jitter))
        time.sleep(d)
print("done")
PY
