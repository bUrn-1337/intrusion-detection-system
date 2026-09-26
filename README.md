# intrusion-detection-system

A network intrusion detection system (IDS) written in Go. It captures packets
from a live interface or a `.pcap` file, decodes them layer by layer
(Ethernet/IP, TCP/UDP/ICMP, HTTP/DNS/FTP), evaluates each decoded packet
against Snort-style rules loaded from `rules.conf`, and reports matches through
a log writer and dashboard. The system is split into six modules that
communicate through a single shared `packet.ParsedPacket` type.

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
make run ARGS="-i eth0"   # bin/ids run with ARGS, without rebuilding
```

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

## Status

| # | Module              | Package                 | Status      |
|---|---------------------|-------------------------|-------------|
| 1 | Packet capture      | `internal/capture`      | Done        |
| 2 | Ethernet/IP parsing | `internal/parser/lower` | Done        |
| 3 | TCP/UDP/ICMP parsing| `internal/parser/upper` | Done        |
| 4 | HTTP/DNS/FTP parsing| `internal/parser/app`   | Done        |
| 5 | Rule engine         | `internal/rules`        | Done        |
| 6 | Dashboard + logging | `internal/logging`      | Done        |
