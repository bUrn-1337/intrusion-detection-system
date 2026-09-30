#!/bin/sh
# replay.sh - run every committed capture in demo/captures/ through the IDS
# and confirm each fires its headline detection. This is the offline demo:
# it needs no network, only the repo's rules.conf and feeds/.
#
#   demo/replay.sh                 replay all captures, print a PASS/FAIL table
#   demo/replay.sh -v              also print each capture's alert/incident table
#   demo/replay.sh --dashboard N   replay capture N (e.g. 29) in the live TUI
#   demo/replay.sh --list          list the captures and their headline sid
#
# The IDS binary is $IDS, or bin/ids (run `make build` first). A pcap replay
# needs no capabilities, so a plain `go build` binary works too.
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH= cd -- "$here/.." && pwd)
cd "$root"

IDS=${IDS:-bin/ids}
if [ ! -x "$IDS" ] && ! command -v "$IDS" >/dev/null 2>&1; then
	echo "error: no IDS binary at '$IDS'. Run 'make build' or set IDS=/path/to/ids." >&2
	exit 1
fi

# file | headline sid | kind (alert|incident) | label
manifest='
01-recon-port-scan.pcap|1000401|alert|Recon: vertical SYN port scan
02-recon-host-sweep.pcap|1000402|alert|Recon: horizontal host sweep (port 22)
03-dos-syn-flood.pcap|1000001|alert|DoS: SYN flood from one source
04-dos-udp-flood.pcap|1000012|alert|DoS: UDP flood (byte rate)
05-dos-icmp-smurf.pcap|1000022|alert|DoS: Smurf / ICMP echo flood at a victim
06-dos-land.pcap|1000003|alert|DoS: LAND (src == dst)
07-dos-ping-of-death.pcap|1000703|alert|Evasion: oversize reassembled ping (ping of death)
08-evasion-teardrop.pcap|1000701|alert|Evasion: overlapping-fragment (teardrop)
09-spoof-arp-poison.pcap|1000802|alert|Spoofing: ARP cache poisoning (MAC flip-flop)
10-dns-zone-transfer.pcap|1000101|alert|DNS: zone transfer (AXFR)
11-dns-tunnel.pcap|1000108|alert|DNS: tunnelling (many random subdomains)
12-dns-dga-nxdomain.pcap|1000110|alert|DNS: DGA / NXDOMAIN burst
13-dns-amplification.pcap|1000103|alert|DNS: amplification / reflection
14-web-sqli.pcap|1000210|alert|Web: SQL injection (UNION)
15-web-xss.pcap|1000214|alert|Web: cross-site scripting (script tag)
16-web-path-traversal.pcap|1000217|alert|Web: path traversal (decoded)
17-web-cmd-injection.pcap|1000219|alert|Web: OS command injection
18-web-log4shell.pcap|1000221|alert|Web: Log4Shell JNDI lookup
19-web-shellshock.pcap|1000222|alert|Web: Shellshock in User-Agent
20-dos-slowloris.pcap|1000030|alert|DoS: Slowloris (slow headers)
21-dos-rudy.pcap|1000032|alert|DoS: RUDY (slow POST body)
22-cred-ftp-bruteforce.pcap|1000301|alert|Credential: FTP brute force
23-c2-beacon.pcap|1001101|alert|C2: periodic beacon
24-ti-ip-feed.pcap|1001001|alert|Threat intel: listed IP
25-ti-domain-feed.pcap|1001002|alert|Threat intel: listed domain
26-ti-ja3-feed.pcap|1001003|alert|Threat intel: listed JA3
27-anomaly-baseline-fanout.pcap|1001201|alert|Anomaly: baseline host-fanout spike
28-spoof-ttl-anomaly.pcap|1000601|alert|Spoofing: TTL anomaly
29-incident-kill-chain.pcap|1001301|incident|Correlation: recon -> exploit -> C2 kill chain
30-incident-callback.pcap|1001303|incident|Correlation: exploited host calls back
'

rows() { printf '%s\n' "$manifest" | sed '/^$/d'; }

if [ "${1:-}" = "--list" ]; then
	rows | while IFS='|' read -r file sid kind label; do
		printf '%-34s sid %-8s %-9s %s\n' "$file" "$sid" "$kind" "$label"
	done
	exit 0
fi

if [ "${1:-}" = "--dashboard" ] || [ "${1:-}" = "--tui" ]; then
	n=${2:?usage: demo/replay.sh --dashboard N}
	file=$(rows | sed -n "${n}p" | cut -d'|' -f1)
	[ -n "$file" ] || { echo "no capture number $n" >&2; exit 1; }
	echo "Live dashboard for demo/captures/$file  (press i to toggle incidents, q to quit)"
	exec "$IDS" run -r "demo/captures/$file" -rules rules.conf
fi

verbose=0
[ "${1:-}" = "-v" ] && verbose=1

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
pass=0
fail=0

# Read from a file, not a pipe, so pass/fail survive in this shell.
rows > "$tmp/manifest"
while IFS='|' read -r file sid kind label; do
	log="$tmp/${file%.pcap}.jsonl"
	if ! "$IDS" run -r "demo/captures/$file" -rules rules.conf -no-tui -log "$log" >/dev/null 2>&1; then
		printf 'FAIL  %-34s ids run failed\n' "$file"
		fail=$((fail + 1))
		continue
	fi
	hit=$("$IDS" query -log "$log" -type all -kind "$kind" -sid "$sid" -json 2>/dev/null | grep -c . || true)
	if [ "${hit:-0}" -ge 1 ]; then
		printf 'PASS  %-34s sid %-8s %s\n' "$file" "$sid" "$label"
		pass=$((pass + 1))
	else
		printf 'FAIL  %-34s sid %-8s %s: no %s record\n' "$file" "$sid" "$label" "$kind"
		fail=$((fail + 1))
	fi
	if [ "$verbose" -eq 1 ]; then
		"$IDS" query -log "$log" -type all -severity low 2>/dev/null | sed 's/^/      /'
		echo
	fi
done < "$tmp/manifest"

echo "----"
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
