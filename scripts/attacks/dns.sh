#!/usr/bin/env bash
# dns.sh - DNS attacks with dig against a lab resolver/server.
# Needs: dig (bind9-dnsutils / bind-utils).
# Triggers: axfr    sid 1000101 (zone transfer request),
#           tunnel  sid 1000108 (many random subdomains of one domain).
# NXDOMAIN/DGA bursts are in dga.sh (sid 1000110).
. "$(cd "$(dirname "$0")" && pwd)/_lib.sh"

usage() { cat <<U
Usage: $PROG --i-have-authorization -t TARGET [-m axfr|tunnel] [-z ZONE] [-d DOMAIN] [-n COUNT]
  -m MODE     axfr (default) or tunnel
  -z ZONE     zone to transfer in axfr mode (default lab.example)
  -d DOMAIN   base domain in tunnel mode (default tunnel.lab.example)
  -n COUNT    queries in tunnel mode (default 80)
U
}

TARGET=""; MODE=axfr; ZONE=lab.example; DOMAIN=tunnel.lab.example; COUNT=80
while [ $# -gt 0 ]; do
  case $1 in
    --i-have-authorization) AUTHORIZED=1 ;;
    -t|--target) TARGET=${2:?}; shift ;;
    -m|--mode) MODE=${2:?}; shift ;;
    -z|--zone) ZONE=${2:?}; shift ;;
    -d|--domain) DOMAIN=${2:?}; shift ;;
    -n|--count) COUNT=${2:?}; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1 (see --help)" ;;
  esac
  shift
done

need_tool dig "install bind9-dnsutils (Debian) or bind-utils (RHEL)"
authorize "$TARGET"
case $MODE in
  axfr)
    set -x
    exec dig AXFR "$ZONE" "@$TARGET"
    ;;
  tunnel)
    echo "tunnel: $COUNT random subdomains of $DOMAIN via $TARGET" >&2
    for i in $(seq 1 "$COUNT"); do
      label=$(head -c16 /dev/urandom | base32 2>/dev/null | tr -d '=' | tr 'A-Z' 'a-z' | head -c40)
      dig +tries=1 +time=1 +short "${label}.${DOMAIN}" "@$TARGET" >/dev/null 2>&1 || true
    done
    echo "done" >&2
    ;;
  *) die "unknown mode: $MODE" ;;
esac
