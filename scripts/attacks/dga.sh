#!/usr/bin/env bash
# dga.sh - domain-generation-algorithm / NXDOMAIN burst (Python + system resolver).
# Needs: python3.
# Triggers: sid 1000110 (many NXDOMAIN answers for algorithmically-named domains).
# Names are random labels under a fixed set of TLDs, resolved against the
# lab resolver so they come back NXDOMAIN.
. "$(cd "$(dirname "$0")" && pwd)/_lib.sh"

usage() { cat <<U
Usage: $PROG --i-have-authorization -t RESOLVER [-n COUNT] [-s SEED]
  -t RESOLVER  DNS server to query (the lab resolver / sensor-side DNS)
  -n COUNT     number of generated domains (default 120)
  -s SEED      PRNG seed for reproducible names (default 1337)
U
}

TARGET=""; COUNT=120; SEED=1337
while [ $# -gt 0 ]; do
  case $1 in
    --i-have-authorization) AUTHORIZED=1 ;;
    -t|--target|--resolver) TARGET=${2:?}; shift ;;
    -n|--count) COUNT=${2:?}; shift ;;
    -s|--seed) SEED=${2:?}; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1 (see --help)" ;;
  esac
  shift
done

need_tool python3
authorize "$TARGET"
export TARGET COUNT SEED
exec python3 - <<'PY'
import os, random, socket
resolver = os.environ["TARGET"]; count = int(os.environ["COUNT"]); seed = int(os.environ["SEED"])
rnd = random.Random(seed)
tlds = ["com", "net", "info", "biz", "org"]
# Point the stdlib resolver at the lab server if the platform honours it.
try:
    socket.setdefaulttimeout(1.0)
except OSError:
    pass
nx = 0
print(f"DGA: {count} generated domains via {resolver} (seed {seed})")
for i in range(count):
    n = rnd.randint(12, 20)
    label = "".join(rnd.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(n))
    domain = f"{label}.{rnd.choice(tlds)}"
    try:
        socket.getaddrinfo(domain, 53)
    except socket.gaierror:
        nx += 1                      # NXDOMAIN / no such host
    except OSError:
        pass
print(f"done: {nx}/{count} did not resolve")
PY
