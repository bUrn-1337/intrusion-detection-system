#!/usr/bin/env bash
# run-all.sh - drive the whole attack toolkit against one lab victim.
#
# AUTHORIZED LAB USE ONLY. This runs the individual scripts in sequence with
# labels and pauses so an operator can watch the sensor light up. It refuses
# to start without --i-have-authorization and a private-range victim, and each
# child script re-checks the same guard. Run this from the ATTACKER machine;
# the victim/sensor is a second host. Do not point it at anything you do not
# own and have written permission to test.
#
#   run-all.sh --i-have-authorization -t 192.168.56.20              full catalogue
#   run-all.sh --i-have-authorization -t 192.168.56.20 --kill-chain recon->exploit->callback
#   run-all.sh --i-have-authorization -t 192.168.56.20 -g 192.168.56.1   (arp needs a gateway)
. "$(cd "$(dirname "$0")" && pwd)/_lib.sh"
DIR=$(cd "$(dirname "$0")" && pwd)

usage() { cat <<U
Usage: $PROG --i-have-authorization -t VICTIM [options]
  -t VICTIM        the lab target (private range)
  -g GATEWAY       gateway to impersonate for the ARP step (default: skip ARP)
  --web-port PORT  victim HTTP port for web/slow/beacon (default 8080)
  --dns TARGET     resolver/DNS server to use (default: VICTIM)
  --kill-chain     only recon -> web exploit -> beacon callback, one narrative
  --pause SECONDS  pause between steps (default 4)
  -y, --yes        do not wait for Enter between steps (still pauses --pause)
Runs the attack scripts in scripts/attacks/ in order. Each is authorized
independently; this driver just sequences and labels them.
U
}

VICTIM=""; GATEWAY=""; WEBPORT=8080; DNS=""; KILL=0; PAUSE=4; YES=0
while [ $# -gt 0 ]; do
  case $1 in
    --i-have-authorization) AUTHORIZED=1 ;;
    -t|--target|--victim) VICTIM=${2:?}; shift ;;
    -g|--gateway) GATEWAY=${2:?}; shift ;;
    --web-port) WEBPORT=${2:?}; shift ;;
    --dns) DNS=${2:?}; shift ;;
    --kill-chain) KILL=1 ;;
    --pause) PAUSE=${2:?}; shift ;;
    -y|--yes) YES=1 ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1 (see --help)" ;;
  esac
  shift
done

authorize "$VICTIM"
[ -n "$DNS" ] || DNS=$VICTIM
AUTH=--i-have-authorization

step() { # step "label" script args...
  local label=$1; shift
  echo
  echo "============================================================"
  echo ">>> $label"
  echo "    $*"
  echo "============================================================"
  if [ "$YES" -eq 0 ]; then
    printf 'Press Enter to run this step (Ctrl-C to abort)... '
    read -r _ || true
  fi
  "$@" || echo "(step exited non-zero: $label)"
  # brief settle so alerts flush before the next step
  timeout "$PAUSE" tail -f /dev/null 2>/dev/null || true
}

if [ "$KILL" -eq 1 ]; then
  echo "KILL CHAIN against $VICTIM: recon -> web exploit -> beacon callback"
  step "1/3 Recon: service scan"        "$DIR/recon.sh"        $AUTH -t "$VICTIM"
  step "2/3 Exploit: web app attacks"   "$DIR/web-attacks.sh"  $AUTH -t "$VICTIM" -p "$WEBPORT"
  step "3/3 Callback: periodic beacon"  "$DIR/beacon.sh"       $AUTH -t "$VICTIM" -p "$WEBPORT" -i 60 -c 6
  echo; echo "kill chain done - expect a correlated incident on the sensor."
  exit 0
fi

echo "FULL CATALOGUE against $VICTIM (DNS $DNS, web port $WEBPORT)"
step "Recon: nmap scan"                "$DIR/recon.sh"        $AUTH -t "$VICTIM"
step "DoS: SYN flood"                  "$DIR/syn-flood.sh"    $AUTH -t "$VICTIM"
step "DoS: UDP flood"                  "$DIR/udp-flood.sh"    $AUTH -t "$VICTIM"
step "DoS: ICMP flood"                 "$DIR/icmp-flood.sh"   $AUTH -t "$VICTIM"
step "DoS: LAND"                       "$DIR/land.sh"         $AUTH -t "$VICTIM"
step "Evasion: fragmentation"          "$DIR/frag.sh"         $AUTH -t "$VICTIM"
step "Spoofing: forged-source flood"   "$DIR/spoofed-flood.sh" $AUTH -t "$VICTIM"
step "DoS: Slowloris (slow headers)"   "$DIR/slowloris.sh"    $AUTH -t "$VICTIM" -p "$WEBPORT" -m headers -s 30
step "DoS: RUDY (slow body)"           "$DIR/slowloris.sh"    $AUTH -t "$VICTIM" -p "$WEBPORT" -m body -s 30
step "DNS: zone transfer"              "$DIR/dns.sh"          $AUTH -t "$DNS" -m axfr
step "DNS: tunnelling"                 "$DIR/dns.sh"          $AUTH -t "$DNS" -m tunnel
step "DNS: DGA / NXDOMAIN burst"       "$DIR/dga.sh"          $AUTH -t "$DNS"
step "Web: application attacks"        "$DIR/web-attacks.sh"  $AUTH -t "$VICTIM" -p "$WEBPORT"
step "C2: periodic beacon"             "$DIR/beacon.sh"       $AUTH -t "$VICTIM" -p "$WEBPORT" -i 60 -c 6
if [ -n "$GATEWAY" ]; then
  step "Spoofing: ARP poisoning"       "$DIR/arp-spoof.sh"    $AUTH -t "$VICTIM" -g "$GATEWAY"
else
  echo; echo "(skipping ARP poisoning: no -g GATEWAY given)"
fi
echo; echo "catalogue done."
