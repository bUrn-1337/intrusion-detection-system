#!/bin/sh
# feeds.sh - download public threat-intel feeds and convert them to the
# IDS feed format (docs/RULES.md#feed): one IP/CIDR, domain or JA3 hash
# per line, '#' comments. Run with "make feeds"; never run by the tests.
#
# Sources and their terms (checked 2026-09-28; read them again before
# using the data commercially):
#   feodo_ip.txt       abuse.ch Feodo Tracker botnet C2 IP blocklist.
#                      CC0: "commercial and non-commercial purpose without
#                      any limitations" (https://feodotracker.abuse.ch/blocklist/).
#   urlhaus_domain.txt abuse.ch URLhaus host file (malware-distribution
#                      hostnames). Free under the abuse.ch fair use
#                      principles (https://abuse.ch/terms-of-use/):
#                      not-for-profit use; commercial users may need a
#                      paid subscription.
#   sslbl_ja3.txt      abuse.ch SSLBL JA3 fingerprint blacklist. CC0
#                      (https://sslbl.abuse.ch/blacklist/). Frozen since
#                      2021-08-03: still useful for old families, no
#                      longer updated.
#   spamhaus_drop.txt  Spamhaus DROP (IPv4 and IPv6): netblocks run by
#                      criminals. Free under the DROP Terms of Use
#                      (https://www.spamhaus.org/drop/terms/), which
#                      forbid using the Spamhaus name in marketing. Do not
#                      download more than once an hour.
#
# Each file is replaced only after its download and conversion succeed,
# so a failed run keeps the previous file (and its age, which the IDS
# reports as stale after max_age).
set -eu

DIR=${FEEDS_DIR:-feeds}
CURL="curl -fsSL --retry 2 --max-time 120 -A ids-feeds/1"
mkdir -p "$DIR"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
failed=0
now=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# fetch NAME URL... : download each URL, concatenated, into $tmp/NAME.raw.
fetch() {
	name=$1
	shift
	: >"$tmp/$name.raw"
	for url in "$@"; do
		if ! $CURL "$url" >>"$tmp/$name.raw"; then
			echo "feeds: $name: download of $url failed; keeping the old file" >&2
			return 1
		fi
	done
}

# put_feed NAME SOURCE TERMS: move $tmp/NAME.txt into place with a header,
# unless it has no entries.
put_feed() {
	n=$(grep -c . "$tmp/$1.txt" || true)
	if [ "$n" -eq 0 ]; then
		echo "feeds: $1: no entries (format changed?); keeping the old file" >&2
		failed=1
		return
	fi
	{
		echo "# $2"
		echo "# Terms: $3"
		echo "# Downloaded $now by scripts/feeds.sh; $n entries."
		cat "$tmp/$1.txt"
	} >"$tmp/$1.out"
	mv "$tmp/$1.out" "$DIR/$1.txt"
	echo "feeds: $DIR/$1.txt: $n entries"
}

# Feodo: one IPv4 address per line, '#' comments.
if fetch feodo_ip https://feodotracker.abuse.ch/downloads/ipblocklist.txt; then
	grep -v '^#' "$tmp/feodo_ip.raw" | tr -d '\r' | awk 'NF {print $1}' >"$tmp/feodo_ip.txt"
	put_feed feodo_ip "abuse.ch Feodo Tracker botnet C2 IPs, https://feodotracker.abuse.ch/downloads/ipblocklist.txt" \
		"CC0, https://feodotracker.abuse.ch/blocklist/"
else failed=1; fi

# URLhaus: hosts-file lines "127.0.0.1<TAB>hostname".
if fetch urlhaus_domain https://urlhaus.abuse.ch/downloads/hostfile/; then
	grep -v '^#' "$tmp/urlhaus_domain.raw" | tr -d '\r' | awk 'NF >= 2 {print $2}' >"$tmp/urlhaus_domain.txt"
	put_feed urlhaus_domain "abuse.ch URLhaus malware hosts, https://urlhaus.abuse.ch/downloads/hostfile/" \
		"abuse.ch fair use principles, https://abuse.ch/terms-of-use/"
else failed=1; fi

# SSLBL: CSV "ja3_md5,Firstseen,Lastseen,Listingreason"; keep the hash and
# the family as the label.
if fetch sslbl_ja3 https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv; then
	grep -v '^#' "$tmp/sslbl_ja3.raw" | tr -d '\r' | awk -F, 'NF >= 4 {print $1 "," $4}' >"$tmp/sslbl_ja3.txt"
	put_feed sslbl_ja3 "abuse.ch SSLBL JA3 fingerprints (frozen since 2021-08-03), https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv" \
		"CC0, https://sslbl.abuse.ch/blacklist/"
else failed=1; fi

# Spamhaus DROP: JSON lines {"cidr":"1.10.16.0/20","sblid":...}; the last
# line is metadata without a cidr.
if fetch spamhaus_drop https://www.spamhaus.org/drop/drop_v4.json https://www.spamhaus.org/drop/drop_v6.json; then
	sed -n 's/.*"cidr":"\([0-9A-Fa-f.:/]*\)".*/\1/p' "$tmp/spamhaus_drop.raw" >"$tmp/spamhaus_drop.txt"
	put_feed spamhaus_drop "Spamhaus DROP v4+v6, https://www.spamhaus.org/drop/" \
		"Spamhaus DROP Terms of Use, https://www.spamhaus.org/drop/terms/"
else failed=1; fi

exit $failed
