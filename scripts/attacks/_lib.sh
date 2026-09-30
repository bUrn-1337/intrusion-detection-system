#!/usr/bin/env bash
# _lib.sh - shared guardrails for the attack-generation toolkit.
#
#   ##############################################################
#   #  AUTHORIZED LAB USE ONLY.                                  #
#   #  These scripts generate real attack traffic to exercise    #
#   #  the IDS. Run them only against machines you own or are    #
#   #  explicitly authorized to test, on a private/lab network.  #
#   #  Every script refuses to run unless BOTH hold:             #
#   #    * you pass --i-have-authorization                       #
#   #    * the target is a private/lab address (see below)       #
#   ##############################################################
#
# Source this from a script:  . "$(dirname "$0")/_lib.sh"
# Then, after parsing args, call:  authorize "$TARGET"
#
# Allowed target ranges (fail-closed: anything else is refused):
#   10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16   RFC 1918 private
#   127.0.0.0/8                                  loopback
#   169.254.0.0/16                               link-local
#   100.64.0.0/10                                CGNAT (RFC 6598)
#   192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24  TEST-NET docs
#   198.18.0.0/15                                benchmarking (RFC 2544)
set -euo pipefail

PROG=$(basename "$0")
AUTHORIZED=0   # set to 1 by --i-have-authorization

die() { echo "$PROG: $*" >&2; exit 2; }

banner() {
	cat >&2 <<'B'
 -------------------------------------------------------------------
  ATTACK TRAFFIC GENERATOR - AUTHORIZED LAB USE ONLY
  Point this only at a machine you own or are authorized to test.
 -------------------------------------------------------------------
B
}

need_tool() {
	# need_tool CMD [install hint]
	command -v "$1" >/dev/null 2>&1 || die "requires '$1' (${2:-install it and retry})"
}

need_root() {
	[ "$(id -u)" -eq 0 ] || die "raw-packet crafting needs root; re-run with sudo (on your own lab host)"
}

# ipv4_to_int A.B.C.D -> integer, or empty on a malformed address.
ipv4_to_int() {
	local ip=$1 a b c d
	IFS=. read -r a b c d <<<"$ip" || return 1
	for o in "$a" "$b" "$c" "$d"; do
		[[ $o =~ ^[0-9]+$ ]] || return 1
		((o >= 0 && o <= 255)) || return 1
	done
	echo $(( (a << 24) + (b << 16) + (c << 8) + d ))
}

# in_cidr INT BASE MASKBITS
in_cidr() {
	local ip=$1 base=$2 bits=$3
	local mask=$(( bits == 0 ? 0 : (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF ))
	(( (ip & mask) == (base & mask) ))
}

is_private_ipv4() {
	local ip int
	ip=$1
	int=$(ipv4_to_int "$ip") || return 1
	[ -n "$int" ] || return 1
	in_cidr "$int" "$(ipv4_to_int 10.0.0.0)"      8  && return 0
	in_cidr "$int" "$(ipv4_to_int 172.16.0.0)"    12 && return 0
	in_cidr "$int" "$(ipv4_to_int 192.168.0.0)"   16 && return 0
	in_cidr "$int" "$(ipv4_to_int 127.0.0.0)"     8  && return 0
	in_cidr "$int" "$(ipv4_to_int 169.254.0.0)"   16 && return 0
	in_cidr "$int" "$(ipv4_to_int 100.64.0.0)"    10 && return 0
	in_cidr "$int" "$(ipv4_to_int 192.0.2.0)"     24 && return 0
	in_cidr "$int" "$(ipv4_to_int 198.51.100.0)"  24 && return 0
	in_cidr "$int" "$(ipv4_to_int 203.0.113.0)"   24 && return 0
	in_cidr "$int" "$(ipv4_to_int 198.18.0.0)"    15 && return 0
	return 1
}

# authorize TARGET - the gate every script calls before sending anything.
authorize() {
	local target=${1:-}
	[ -n "$target" ] || die "no target given (see --help)"
	if [ "$AUTHORIZED" -ne 1 ]; then
		die "refusing to run without --i-have-authorization (target $target).
    These scripts send real attack traffic. Confirm you own or are
    authorized to test $target, then re-run with --i-have-authorization."
	fi
	if ! is_private_ipv4 "$target"; then
		die "refusing: $target is not a private/lab address.
    Allowed: RFC1918, loopback, link-local, CGNAT, TEST-NET and 198.18/15.
    Point the demo at a lab host on one of those ranges."
	fi
	banner
	echo "$PROG: authorized run against $target" >&2
}

# take_auth_flag - call in the arg loop: consumes --i-have-authorization.
# Usage:  case $1 in ...) if take_auth_flag "$1"; then shift; continue; fi ;; esac
take_auth_flag() {
	[ "$1" = "--i-have-authorization" ] && { AUTHORIZED=1; return 0; }
	return 1
}
