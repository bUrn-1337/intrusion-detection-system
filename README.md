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

```
make build   # go build -o bin/ids ./cmd/ids
make test    # go test ./...
make lint    # go vet + staticcheck (if installed)
make run     # placeholder until the integration step
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the branch workflow.

## Status

| # | Module              | Package                 | Status      |
|---|---------------------|-------------------------|-------------|
| 1 | Packet capture      | `internal/capture`      | Not started |
| 2 | Ethernet/IP parsing | `internal/parser/lower` | Not started |
| 3 | TCP/UDP/ICMP parsing| `internal/parser/upper` | Not started |
| 4 | HTTP/DNS/FTP parsing| `internal/parser/app`   | Not started |
| 5 | Rule engine         | `internal/rules`        | Not started |
| 6 | Dashboard + logging | `internal/logging`      | Not started |
