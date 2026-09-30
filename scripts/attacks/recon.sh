#!/usr/bin/env bash
# recon.sh - reconnaissance scans with nmap.
# Needs: nmap (SYN scan needs root/CAP_NET_RAW).
# Triggers on the sensor:
#   portscan  sid 1000401  Port scan            (many ports, one target)
#   sweep     sid 1000402  Host sweep of one port (one port, many hosts)
#   ping      sid 1000403  Ping sweep
. "$(cd "$(dirname "$0")" && pwd)/_lib.sh"

usage() { cat <<U
Usage: $PROG --i-have-authorization -t TARGET [-m portscan|sweep|ping] [-p PORT]
  -t TARGET   lab host (portscan) or a host whose /24 is swept (sweep/ping)
  -m MODE     portscan (default), sweep, or ping
  -p PORT     port for sweep mode (default 22)
Examples:
  $PROG --i-have-authorization -t 192.168.56.20
  $PROG --i-have-authorization -t 192.168.56.20 -m sweep -p 22
U
}

TARGET=""; MODE=portscan; PORT=22
while [ $# -gt 0 ]; do
  case $1 in
    --i-have-authorization) AUTHORIZED=1 ;;
    -t|--target) TARGET=${2:?}; shift ;;
    -m|--mode) MODE=${2:?}; shift ;;
    -p|--port) PORT=${2:?}; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1 (see --help)" ;;
  esac
  shift
done

need_tool nmap "install nmap"
authorize "$TARGET"
net=${TARGET%.*}.0/24
set -x
case $MODE in
  portscan) exec nmap -sS -T4 -p 1-1024 "$TARGET" ;;
  sweep)    exec nmap -sS -T4 -p "$PORT" "$net" ;;
  ping)     exec nmap -sn -PE "$net" ;;
  *) set +x; die "unknown mode: $MODE" ;;
esac
