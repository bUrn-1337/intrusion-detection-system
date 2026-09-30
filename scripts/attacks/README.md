# Attack scripts — authorized lab use only

These scripts drive traffic at a **second machine** (the victim/sensor) so you
can watch this project's IDS detect it on a real network. They are the
active-testing counterpart to the offline `demo/` replays.

> **Authorized use only.** Every script refuses to run unless you pass
> `--i-have-authorization` **and** the target is on a private/lab range
> (RFC 1918, loopback, link-local, CGNAT, and the RFC 5737/2544 documentation
> ranges). Run them only against hosts you own and have written permission to
> test. Do **not** point them at the internet or at anyone else's systems.
> The sensor runs on the victim; the scripts run on a separate attacker host.
> `docs/DEMO.md` describes the two-machine setup.

All scripts share `_lib.sh` (the authorization guard and small helpers).
`-h` / `--help` works without authorization and prints per-script usage.

## Guard behaviour

* No `--i-have-authorization` → exits with an error, runs nothing.
* Target not on a private/lab range → exits with an error, runs nothing.
* Otherwise it prints a one-line "AUTHORIZED" banner naming the target, then runs.

## Scripts

| Script | Needs | What it does | Triggers (sid) |
|---|---|---|---|
| `recon.sh` | nmap | TCP SYN / service scan of the victim | 1000401 vertical scan, 1000402 horizontal sweep |
| `syn-flood.sh` | hping3, root | high-rate TCP SYN flood | 1000001 SYN flood |
| `udp-flood.sh` | hping3, root | high-rate UDP flood | 1000012 UDP byte-rate flood |
| `icmp-flood.sh` | hping3, root | ICMP echo flood at the victim | 1000022 ICMP/smurf flood |
| `land.sh` | scapy, root | LAND packet (src == dst) | 1000003 LAND |
| `frag.sh` | scapy, root | teardrop / tiny-frag / ping-of-death / frag flood | 1000701 teardrop, 1000703 ping of death |
| `spoofed-flood.sh` | scapy, root | flood from forged 198.18/15 sources | 1000601 TTL/spoof anomaly, plus the flood sid for the mode |
| `slowloris.sh` | python3 | slow HTTP headers (`-m headers`) or slow body (`-m body`) | 1000030 Slowloris, 1000032 RUDY |
| `dns.sh` | dig | zone transfer (`-m axfr`) or tunnelling (`-m tunnel`) | 1000101 AXFR, 1000108 tunnelling |
| `dga.sh` | python3 | DGA / NXDOMAIN burst via the lab resolver | 1000110 DGA/NXDOMAIN |
| `web-attacks.sh` | curl | SQLi / XSS / traversal / cmd-inj / Log4Shell / Shellshock | 1000210, 1000214, 1000217, 1000219, 1000221, 1000222 |
| `arp-spoof.sh` | arpspoof *or* scapy, root | ARP cache poisoning of the victim | 1000802 changed MAC, 1000803 flip-flop, 1000804 unsolicited reply |
| `beacon.sh` | python3 | periodic C2-style callback | 1001101 periodic beacon |
| `run-all.sh` | the above | sequences the catalogue with labels/pauses; `--kill-chain` = recon→exploit→callback | correlated incident (1001301 / 1001303) on top of the above |

The exact alert text for each sid is in `rules.conf`. Some scripts fire more
than the headline sid (for example a flood also trips rate and anomaly rules);
the table lists the ones each script is written to demonstrate.

## Typical run

On the **attacker** machine, with the sensor already capturing on the victim:

```sh
# one attack
scripts/attacks/recon.sh --i-have-authorization -t 192.168.56.20

# the whole catalogue, pausing between steps
scripts/attacks/run-all.sh --i-have-authorization -t 192.168.56.20 -g 192.168.56.1

# just the kill chain (recon -> web exploit -> beacon callback)
scripts/attacks/run-all.sh --i-have-authorization -t 192.168.56.20 --kill-chain
```

Tools not present are reported by name (with an install hint) before anything
runs. Steps that need raw sockets (`hping3`, `scapy`, `arpspoof`) must be run as
root on the attacker; the scripts say so and stop early if they are not.

## No credentials

`web-attacks.sh` and the others never send real credentials. The FTP
brute-force and other credential scenarios are exercised offline from
`demo/captures/` instead, and the sensor is built to keep credentials out of
its own alerts and logs.
