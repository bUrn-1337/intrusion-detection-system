# intrusion-detection-system

A network intrusion detection system (IDS) written in Go. It captures packets
from a live interface or a `.pcap` file, decodes them layer by layer
(Ethernet/IP, TCP/UDP/ICMP, HTTP/DNS/FTP), evaluates each decoded packet
against Snort-style rules loaded from `rules.conf`, and reports matches through
a log writer and dashboard. The system is split into six modules that
communicate through a single shared `packet.ParsedPacket` type.

## Quick start

```
sudo apt install libpcap-dev
make build
bin/ids run -r trace.pcap -no-tui  # replay any Ethernet pcap or pcapng
make setcap                        # once per build, for live capture
bin/ids run -i eth0                # live, with the dashboard
bin/ids query -severity high       # read the alert log
```

## Documentation

| doc | contents |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | pipeline, the ParsedPacket contract, design decisions |
| [docs/RULES.md](docs/RULES.md) | the rule language, every option with an example |
| [docs/ADDING_A_DETECTOR.md](docs/ADDING_A_DETECTOR.md) | step-by-step template for a new stateful detector |
| [docs/SCENARIOS.md](docs/SCENARIOS.md) | end-to-end alert tests and how to add one |
| [docs/DEMO.md](docs/DEMO.md) | running the IDS live between two machines, and the offline replay |

## Pipeline

```
 [1] Capture           internal/capture       raw frames (iface / .pcap)
        |
        v
 [2] Lower parser      internal/parser/lower  Ethernet, IPv4/IPv6
        |
        v
 [3] Upper parser      internal/parser/upper  TCP, UDP, ICMP
        |
        v
 [4] App parser        internal/parser/app    HTTP, DNS, FTP
        |
        v
 [5] Rule engine       internal/rules         match against rules.conf
        |
        v
 [6] Logging           internal/logging       alert log + dashboard

 Shared type: internal/packet (ParsedPacket) — imported by all, imports nothing internal
 Entry point: cmd/ids
```

## Detections

The engine ships **83 detection rules** in `rules.conf`, grouped below. Severity and the matching keyword/option set are in [docs/RULES.md](docs/RULES.md); each has a firing scenario and a benign look-alike under `testdata/scenarios/`.

#### Reconnaissance (11)

| sid | sev | proto | detection |
|-----|-----|-------|-----------|
| 1000101 | medium | IP | DNS zone transfer (AXFR) request |
| 1000224 | medium | TCP | Web scanner User-Agent |
| 1000401 | medium | IP | Port scan |
| 1000402 | medium | IP | Host sweep of one port |
| 1000403 | low | ICMP | Ping sweep |
| 1000404 | high | TCP | TCP NULL scan packet (no flags) |
| 1000405 | high | TCP | TCP Xmas scan packet (FIN+PSH+URG) |
| 1000406 | high | TCP | TCP SYN+FIN packet |
| 1000407 | low | ICMP | IPv6 Echo Request to multicast |
| 1000408 | low | ICMP | Traceroute (repeated ICMP Time Exceeded) |
| 1000409 | low | IP | Low TTL from external source |

#### Denial of service (23)

| sid | sev | proto | detection |
|-----|-----|-------|-----------|
| 1000001 | high | TCP | SYN flood against one destination |
| 1000002 | high | TCP | SYN flood from one source |
| 1000003 | high | TCP | Land attack (TCP SYN to itself) |
| 1000004 | medium | IP | IP packet with source equal to destination |
| 1000005 | high | ICMP | Smurf: Echo Request to Ethernet broadcast |
| 1000006 | high | ICMP | Smurf: Echo Request to 255.255.255.255 |
| 1000010 | high | UDP | UDP flood against one destination |
| 1000011 | high | UDP | UDP flood from one source |
| 1000012 | high | UDP | UDP flood against one destination (bytes) |
| 1000013 | high | UDP | UDP reflection/amplification from reflector ports |
| 1000020 | high | ICMP | ICMP Echo flood against one destination |
| 1000021 | high | ICMP | ICMP Echo flood from one source |
| 1000022 | high | ICMP | Unsolicited ICMP Echo Replies (smurf victim) |
| 1000023 | medium | ICMP | ICMP error flood |
| 1000030 | high | TCP | Slowloris (slow HTTP headers) from one source |
| 1000031 | high | TCP | Slowloris (slow HTTP headers) against one server |
| 1000032 | high | TCP | Slow HTTP POST (R-U-Dead-Yet) |
| 1000033 | high | TCP | Slow HTTP read (zero window) |
| 1000106 | high | IP | DNS amplification against one victim |
| 1000107 | medium | IP | Repeated DNS ANY queries |
| 1000701 | high | IP | Overlapping IP fragments |
| 1000703 | high | IP | Oversized IP fragment (ping of death) |
| 1000704 | medium | IP | IP fragment flood (incomplete datagrams) |

#### Evasion / IDS bypass (3)

| sid | sev | proto | detection |
|-----|-----|-------|-----------|
| 1000223 | high | TCP | HTTP URI with overlong UTF-8 encoding |
| 1000501 | high | TCP | TCP overlapping segment with different data |
| 1000702 | high | IP | Tiny IP fragment |

#### Spoofing (11)

| sid | sev | proto | detection |
|-----|-----|-------|-----------|
| 1000103 | high | IP | DNS responses answering no query |
| 1000104 | critical | IP | DNS id race (forged answers guessing ids) |
| 1000105 | high | IP | DNS response for a different question |
| 1000601 | low | IP | TTL anomaly: likely spoofed source |
| 1000801 | critical | ARP | ARP spoofing: static binding violated |
| 1000802 | low | ARP | ARP binding changed MAC |
| 1000803 | high | ARP | ARP spoofing: binding flip-flopping between MACs |
| 1000804 | high | ARP | ARP spoofing: unsolicited replies |
| 1000805 | medium | ARP | ARP spoofing: one MAC claims many addresses |
| 1000806 | medium | ARP | ARP sender MAC differs from Ethernet source |
| 1000807 | high | ARP | ARP sender MAC is broadcast, multicast or zero |

#### DNS integrity (1)

| sid | sev | proto | detection |
|-----|-----|-------|-----------|
| 1000102 | low | IP | Malformed DNS message |

#### Exfiltration / tunnelling (3)

| sid | sev | proto | detection |
|-----|-----|-------|-----------|
| 1000108 | high | IP | DNS tunnel: many random subdomains of one domain |
| 1000109 | high | IP | DNS tunnel: many TXT/NULL queries to one domain |
| 1000901 | medium | ICMP | ICMP tunnel (non-standard echo payloads) |

#### Web application (14)

| sid | sev | proto | detection |
|-----|-----|-------|-----------|
| 1000202 | medium | TCP | HTTP URI with double percent-encoding |
| 1000210 | high | TCP | SQL injection: UNION SELECT |
| 1000211 | high | TCP | SQL injection: quoted OR tautology |
| 1000212 | high | TCP | SQL injection: time-based delay function |
| 1000213 | high | TCP | SQL injection: information_schema access |
| 1000214 | high | TCP | XSS: <script> tag in URI |
| 1000215 | medium | TCP | XSS: javascript: URL in URI |
| 1000216 | high | TCP | XSS: event handler in URI |
| 1000217 | high | TCP | Path traversal in URI |
| 1000218 | high | TCP | Sensitive system file requested |
| 1000219 | high | TCP | Command injection in query string |
| 1000220 | critical | TCP | Log4Shell JNDI lookup in URI |
| 1000221 | critical | TCP | Log4Shell JNDI lookup in HTTP header |
| 1000222 | critical | TCP | Shellshock function definition in HTTP header |

#### Credentials (3)

| sid | sev | proto | detection |
|-----|-----|-------|-----------|
| 1000201 | medium | TCP | HTTP Basic auth over cleartext |
| 1000301 | medium | TCP | FTP password sent in cleartext |
| 1000302 | high | TCP | FTP brute force (repeated 530 login failures) |

#### Malware / C2 (2)

| sid | sev | proto | detection |
|-----|-----|-------|-----------|
| 1000110 | medium | IP | Burst of NXDOMAIN for random names (DGA) |
| 1001101 | medium | IP | Periodic connections to one destination (possible C2 beacon) |

#### Threat intelligence (4)

| sid | sev | proto | detection |
|-----|-----|-------|-----------|
| 1001001 | high | IP | Traffic with a threat-intel listed address |
| 1001002 | high | IP | Threat-intel listed domain |
| 1001003 | critical | TCP | TLS client fingerprint (JA3) of a known malware family |
| 1001004 | high | TCP | Threat-intel listed TLS client fingerprint (JA3) |

#### Anomaly (3)

| sid | sev | proto | detection |
|-----|-----|-------|-----------|
| 1000502 | medium | TCP | HTTP headers over 16 KiB |
| 1000902 | low | ICMP | Oversized ICMP Echo Request |
| 1001201 | medium | IP | Traffic far above its learned baseline |

#### Policy (2)

| sid | sev | proto | detection |
|-----|-----|-------|-----------|
| 1000111 | low | TCP | DNS over HTTPS to a public resolver |
| 1000112 | low | TCP | DNS over TLS connection |

#### Correlation (incidents) (3)

| sid | sev | proto | detection |
|-----|-----|-------|-----------|
| 1001301 | — | IP | Multi-stage attack |
| 1001302 | — | IP | Host compromised after an exploit |
| 1001303 | — | IP | Exploited host connected back to the attacker |

## Demo

Two ways to see it work, both documented in [docs/DEMO.md](docs/DEMO.md):

- **Offline, no network** — `demo/replay.sh` runs every capture in
  [demo/captures/](demo/captures/) (one per headline detection, plus two
  correlated-incident kill chains) through the pipeline and prints a PASS/FAIL
  table. Representative alert-log, dashboard and `ids query` output for a report
  is in [demo/output/](demo/output/).

  ```
  demo/replay.sh                  # replay all captures, verify each fires
  demo/replay.sh --list           # captures and their headline sid
  demo/replay.sh --dashboard 29   # watch the kill chain in the live TUI
  ```

- **Live, two machines** — an attacker host drives the lab-gated scripts in
  [scripts/attacks/](scripts/attacks/) at a victim/sensor host running the IDS.
  Each script refuses to run without `--i-have-authorization` and a
  private-range target. See
  [scripts/attacks/README.md](scripts/attacks/README.md) for the tools and the
  sid each triggers, and [docs/DEMO.md](docs/DEMO.md) for the VM and
  physical-switch setups.

## Building

Packet capture uses libpcap through cgo
([gopacket/pcap](https://pkg.go.dev/github.com/gopacket/gopacket/pcap)), so
you need a C compiler and the libpcap development headers to build or test:

```
sudo apt install libpcap-dev      # Debian/Ubuntu
sudo dnf install libpcap-devel    # Fedora
brew install libpcap              # macOS (the system libpcap usually works too)
```

Live capture also needs raw-socket privileges. Instead of running as root,
grant them to the binary once after each build:

```
make setcap   # sudo setcap cap_net_raw,cap_net_admin=eip bin/ids cap_net_raw,cap_net_admin=eip bin/capturedump
```

Rebuilding a binary strips its capabilities, so run `make setcap` again after
every `make build`.

Only Ethernet interfaces are supported. The Linux `any` device and macOS
loopback use other link types and are rejected at startup.

```
make build   # builds bin/ids and bin/capturedump (a debug tool: parsed packets + alerts)
make setcap  # grants capture capabilities to both binaries (uses sudo)
make test    # go test ./...
make lint    # go vet + staticcheck (if installed)
make scenarios            # every testdata/scenarios case through ids run
make fuzz FUZZTIME=2m     # fuzz the whole pipeline (default 30s)
make fuzz FUZZ=FuzzStream # fuzz TCP reassembly with segmented scenario traffic
make run ARGS="-i eth0"   # bin/ids run with ARGS, without rebuilding
```

CI ([.github/workflows/ci.yml](.github/workflows/ci.yml)) runs gofmt, vet,
staticcheck, `go test -race ./...`, `make scenarios` and a 30 s fuzz.

## Running

```
bin/ids run -i eth0                        # live capture with the dashboard
bin/ids -i eth0 -no-tui                    # "run" is the default subcommand
bin/ids run -r capture.pcap -no-tui        # replay a pcap file
bin/ids run -i eth0 -f 'tcp or udp port 53' -rules rules.conf \
            -whitelist 10.0.0.0/8,192.168.1.5 \
            -log /var/log/ids.jsonl -log-max-size 50M -log-max-files 10
```

| Flag | Meaning |
|------|---------|
| `-i IFACE` / `-r FILE` | live interface or pcap file (exactly one) |
| `-f BPF` | BPF capture filter |
| `-rules PATH` | rule file (default `rules.conf`) |
| `-whitelist CIDR[,CIDR]` | source addresses that never alert |
| `-log PATH` | JSON Lines log (default `ids-alerts.jsonl`, created mode 0600) |
| `-log-max-size SIZE` | rotate when the log would exceed SIZE (K/M/G suffix, default 100M) |
| `-log-max-files N` | rotated files kept: `PATH.1` (newest) … `PATH.N` (default 5) |
| `-no-tui` | print alerts to stdout, one line each; automatic when stdout is not a terminal |
| `-stats-interval D` | how often a stats record is logged (default 1m) |

Each packet goes through capture → lower → upper → app parsers → rule engine in
a single goroutine (so packet order and TCP handshake tracking are preserved).
Alerts go to the log and to the dashboard or stdout.

- **Reload rules:** `kill -HUP <pid>` or the `r` key. A bad rule file is
  rejected and the old rules stay active; the result is shown in the header
  and logged as an `event` record.
- **Shutdown:** Ctrl-C, SIGTERM or `q` stops capture, drains queued packets,
  flushes pending summaries, writes a final stats record and closes the log.
- Missing or invalid rule files are reported with every error and its line
  number, and nothing is started.

### Dashboard

The dashboard shows the source and uptime, rules loaded and the last reload
result; packets/s and bytes/s (current second and 60 s average); capture
health (captured, kernel drops, queue drops, queue depth, log records
dropped — any non-zero drop count is red, because a dropping IDS is blind);
the protocol breakdown; top talkers by packets and bytes and the top alerting
sources over the last minute; and a scrolling feed of recent alerts colored by
severity.

| Key | Action |
|-----|--------|
| `q` | quit (graceful shutdown) |
| `p` | pause / resume the alert feed |
| `r` | reload rules |

With `-r FILE` the dashboard stays open after the file ends, until `q`.

### Log format

One JSON object per line, with a `type` field:

- `alert`: the rule engine's alert (`kind` is `alert` or `summary`), e.g.
  `{"type":"alert","time":"…","sid":1000001,"msg":"…","severity":"high","category":"dos","proto":"TCP","src_ip":"…","dst_ip":"…","count":1,"kind":"alert",…}`
- `stats`: capture, engine, traffic and log-writer counters; written every
  `-stats-interval` (`"reason":"periodic"`) and at shutdown (`"reason":"shutdown"`).
- `event`: rule reloads (`"event":"reload"`, `ok`, `rules`, `error`).

### Querying the log

```
bin/ids query                                   # all alerts, as a table
bin/ids query -severity high -since 1h          # high and critical, last hour
bin/ids query -src 203.0.113.0/24 -kind summary -json
bin/ids query -from '2026-09-26 10:00' -to '2026-09-26 11:00' -sid 1000001
bin/ids query -type stats -json                 # stats records
bin/ids query -follow -severity medium          # like tail -f; survives rotation
```

Filters: `-severity` (minimum), `-since DURATION` or `-from`/`-to TIME`,
`-src`/`-dst` (IP or CIDR), `-sid`, `-category`, `-kind alert|summary`,
`-type alert|stats|event|all` (default `alert`). The current log and its
rotated files are read oldest first. A partial last line (still being written)
is skipped; other invalid lines are skipped and counted.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the branch workflow.

## Modules and ownership

All six modules are complete. The shared `internal/packet` contract is imported
by every module and imports nothing internal; `cmd/ids` wires the pipeline.

| Area | Primary owner | Enrollment | Also contributed |
|---|---|---|---|
| Capture engine, logging & dashboard (`internal/capture`, `internal/logging`, TUI) | Daddi Om Santosh | 24114028 | — |
| Lower-layer parsers + fragmentation & ARP detectors (`internal/parser/lower`) | Deokar Parth Rajesh | 24114032 | — |
| Upper-layer parsers, TCP stream reassembly + scan/flood detectors (`internal/parser/upper`, `internal/stream`) | Aditya Pratap Singh Bhadoria | 24114005 | Aditya Ranjan |
| Application parsers + web-attack & DNS detectors (`internal/parser/app`) | Aditya Ranjan | 24114006 | Satyam Sharma |
| Rule engine, rule language, detection framework + correlation/incidents (`internal/rules`) | Satyam Sharma | 24114088 | Kothawade Manthan |
| Threat-intel feeds, beaconing/baseline/anomaly detectors + test harness (`internal/intel`, `internal/entropy`, scenarios/fuzz/CI) | Kothawade Manthan | 24114050 | — |

## Contributions

**Daddi Om Santosh (24114028)** built the capture engine (`internal/capture`): the
live AF_PACKET/pcap path and the `.pcap` replay reader, snaplen and promiscuous
handling, the capture ring with its drop-when-full-vs-wait policy, and the
kernel/queue drop accounting. He also owns the output side end to end — the JSONL
logger with size-based rotation (`internal/logging`) and the live terminal
dashboard (`internal/logging/tui`) with its rolling top-N tables and pause/resume.

**Deokar Parth Rajesh (24114032)** owns the lower-layer parser
(`internal/parser/lower`): Ethernet, VLAN-tag walking, IPv4/IPv6 with the IPv6
extension-header chain and fragmentation fields, and ARP decoding. He built the
detectors that key on those layers — the fragmentation/evasion signatures
(teardrop sid 1000701, ping-of-death sid 1000703), the ARP cache-poisoning
detectors (sid 1000802–1000804), and the IP TTL-anomaly spoofing check (sid 1000601).

**Aditya Pratap Singh Bhadoria (24114005)** owns the upper-layer parser
(`internal/parser/upper`, TCP/UDP/ICMP) and the TCP stream-reassembly stage
(`internal/stream`) — the handshake table, application-port flows, and the
overlap-conflict handling that underpins evasion resistance. On top of that he
built the scan and volumetric-flood detectors: vertical/horizontal scans (sid
1000401/1000402) and the SYN/UDP/ICMP/LAND floods (sid 1000001/1000012/1000022/1000003).
His reassembled streams also feed Aditya Ranjan's application parsers.

**Aditya Ranjan (24114006)** owns the application parsers (`internal/parser/app`:
HTTP, DNS, FTP, TLS/JA3) and the web and DNS detectors that run on them:
SQL-injection, XSS, path traversal, command injection, Log4Shell and Shellshock
(sid 1000210–1000223, including the overlong-UTF-8 URI normaliser), the FTP
brute-force check (sid 1000301), and the DNS zone-transfer, amplification, tunnel
and DGA/NXDOMAIN signatures (sid 1000101–1000110). These detectors are expressed
on Satyam Sharma's shared rule framework.

**Satyam Sharma (24114088)** built the detection core: the rule engine and rule
language (`internal/rules`, `rules.conf`), the stateful-detector framework every
other detector plugs into, the packet-time deterministic clock, and the
spoofable-vs-reliable attribution model. He owns correlation and incident
construction — the multi-stage kill-chain and callback logic (sid 1001301/1001303)
with its framing resistance, so a spoofed source cannot manufacture an incident.

**Kothawade Manthan (24114050)** owns threat-intel matching (`internal/intel`:
IP/domain/JA3 feeds, sid 1001001–1001003) and the behavioural detectors —
periodic C2 beaconing (sid 1001101), the statistical host-fanout baseline/anomaly
(sid 1001201), and the entropy engine (`internal/entropy`) behind DGA and tunnel
scoring. He also built the test harness that holds the project together: the
scenario runner and its 145 fixtures, the fuzz targets, the false-positive corpus
and CI.

