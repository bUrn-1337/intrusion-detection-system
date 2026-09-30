#!/usr/bin/env bash
# udp-flood.sh - UDP flood with hping3.
# Needs: hping3, root.
# Triggers: sid 1000010 (UDP flood against one destination),
#           sid 1000011 (from one source), 1000012 (byte rate).
. "$(cd "$(dirname "$0")" && pwd)/_lib.sh"

usage() { cat <<U
Usage: $PROG --i-have-authorization -t TARGET [-p PORT] [-c COUNT] [-d SIZE]
  -p PORT   destination port (default 9999, typically closed)
  -c COUNT  packets to send (default 20000)
  -d SIZE   UDP payload bytes (default 64; raise to trip the byte rule)
U
}

TARGET=""; PORT=9999; COUNT=20000; SIZE=64
while [ $# -gt 0 ]; do
  case $1 in
    --i-have-authorization) AUTHORIZED=1 ;;
    -t|--target) TARGET=${2:?}; shift ;;
    -p|--port) PORT=${2:?}; shift ;;
    -c|--count) COUNT=${2:?}; shift ;;
    -d|--size) SIZE=${2:?}; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1 (see --help)" ;;
  esac
  shift
done

need_tool hping3 "install hping3"
need_root
authorize "$TARGET"
set -x
exec hping3 --udp -p "$PORT" -d "$SIZE" -i u150 -c "$COUNT" "$TARGET"
