# Report content

Write-up material for the team to paste into the report and slides. Everything
here is drawn from the code, the docs and this project's own test/benchmark
runs; numbers are measured, not estimated. Where a value depends on the machine
it was measured on, that is stated.

> **Placeholders to fill in:** the per-module owners (Section 14) and the
> per-member contributions (Section 15) need the team's input. The syllabus
> topic *titles* in Section 4 are our inference — confirm them against the
> course outline; the mapping itself holds regardless.

---

## 1. Abstract

We built a network intrusion detection system (IDS) in Go that captures traffic
from a live interface or a `.pcap` file, decodes it from Ethernet up through
the application layer (HTTP, DNS, FTP, TLS ClientHello), and matches every
packet against a Snort-style rule set. It ships **83 detection rules** spanning
reconnaissance, denial of service, spoofing, DNS abuse, web-application attacks,
credential exposure, malware/C2 beaconing, threat-intel feed matches and
statistical anomalies, and it correlates individual alerts into multi-stage
**incidents**. The system is built as six modules that communicate through a
single shared packet type, runs the whole detection path in one goroutine so
results are deterministic, and keys all timing on the packet capture timestamp
rather than wall-clock time, so replaying a capture reproduces the same alerts
exactly. It processes on the order of 10^5 packets/second single-threaded, holds
a bounded memory footprint under sustained load, and raises zero false positives
on a benign traffic corpus.

## 2. Problem and motivation

A network is attacked in ways that a single packet rarely reveals: a port scan
is many half-open connections, a flood is a rate, a DNS tunnel is a pattern
across queries, and a real intrusion is a *sequence* — reconnaissance, then an
exploit, then a callback. A useful IDS therefore has to (a) decode every layer
correctly and cheaply, (b) hold bounded state across packets to see rates and
sequences, (c) resist evasion (fragmentation, segment overlap, spoofed sources)
and (d) resist being *fooled into blaming the wrong host*. It also has to be
honest about what it cannot know: a forged source address is not evidence. This
project is an end-to-end IDS that takes those four requirements as its design
centre, and a test methodology that tries to prove each detector both fires when
it should and stays quiet when it should not.

## 3. Objectives

1. Capture live and offline traffic and decode Ethernet/IPv4/IPv6, TCP/UDP/ICMP,
   and HTTP/DNS/FTP/TLS, with credential redaction built into the parsers.
2. A Snort-style rule language and engine with stateful detectors (rates,
   scans, floods, slow attacks, tunnels, beacons, baselines).
3. TCP stream reassembly so application signatures survive segmentation, plus
   fragmentation and overlap detection for evasion.
4. An attribution model that separates spoofable from reliable evidence, and a
   correlation layer that builds multi-stage incidents only from reliable
   attackers.
5. Operable output: a live dashboard, a rotating JSON-Lines alert log, and a
   query tool.
6. A test methodology strong enough to trust: per-detector scenarios with benign
   look-alikes, mutation checks, fuzzing, a false-positive corpus, and
   performance/stability measurement.

## 4. Syllabus mapping

The topic titles are our reading of the outline; confirm against the course
syllabus. The project demonstrates each topic as follows.

| Topic | Area (confirm title) | Where the project demonstrates it |
|---|---|---|
| 3 | Network layer — IPv4/IPv6, ICMP, fragmentation | `internal/parser/lower` decodes IP/ARP; fragment tracking and overlap/teardrop/ping-of-death detection (`frag_attack`, sids 1000701–1000704); TTL anomaly (1000601); ICMP flood/smurf/tunnel (1000005–1000023, 1000901) |
| 5 | Transport layer — TCP/UDP | `internal/parser/upper` decodes TCP/UDP with checksum status; handshake tracking; SYN/UDP floods, scans (NULL/Xmas/SYN-FIN), LAND, TCP segment overlap; stream reassembly in `internal/stream` |
| 6 | Application layer — HTTP/DNS/FTP/TLS | `internal/parser/app`; web-attack signatures (SQLi/XSS/traversal/cmd-inj/Log4Shell/Shellshock), DNS AXFR/tunnel/DGA/amplification/spoofing, FTP credential and brute-force, TLS JA3 fingerprinting |
| 7 | Network security — attacks, detection, defence | the whole rule engine, the spoofable-vs-reliable attribution model, correlation into incidents, threat-intel feeds, and the two-machine attack/detect demo (`docs/DEMO.md`, `scripts/attacks/`) |

## 5. Architecture

Six modules connected by a single shared type, driven by one entry point.

```
 [1] Capture           internal/capture       raw frames (iface / .pcap)
        v
 [2] Lower parser      internal/parser/lower  Ethernet, VLAN, IPv4/IPv6, ARP
        v
 [3] Upper parser      internal/parser/upper  TCP, UDP, ICMP/ICMPv6, checksums
        v
     Stream stage      internal/stream        TCP reassembly on app ports
        v
 [4] App parser        internal/parser/app    HTTP, DNS, FTP, TLS ClientHello
        v
 [5] Rule engine       internal/rules         rules, handshakes, dedup,
        |                                      detectors, attribution, correlate
        +--> [6] Logging  internal/logging     JSON-Lines log (rotating) + dashboard

 Shared type: internal/packet (ParsedPacket) — imported by all, imports nothing internal
 Entry point: cmd/ids   (run + query subcommands)
```

Three goroutines: a capture goroutine copies each frame into a fresh
`ParsedPacket` and puts it on a 10,000-deep channel; one **pipeline goroutine**
runs stages 2→stream→4→5 in capture order; a writer goroutine drains alerts to
the log. On a live interface a full queue drops the frame (and counts it),
because the kernel would drop it anyway; on a file, capture waits, so every
packet is processed and results are deterministic. See
[docs/ARCHITECTURE.md](ARCHITECTURE.md).

## 6. The shared-contract design

The only thing the stages share is `internal/packet.ParsedPacket`. The design
rule is **single-writer fields**: each field is written by exactly one stage and
read only by later ones, and the field comments name the owning stage. `RawData`
is a private copy the packet owns, never a libpcap buffer, and no stage mutates
it. This gives three properties:

- **No locks on the hot path.** Because ownership passes downstream with the
  packet and one goroutine runs the whole chain, no stage needs a mutex to read
  an earlier stage's output.
- **Testability.** Each stage is a pure function of the packet so far, so every
  parser and detector is unit-tested in isolation and the whole pipeline is
  driven end-to-end from pcaps.
- **A stable seam for new detectors.** A new detector reads existing fields and
  emits alerts; it never reaches back into an earlier stage. Adding one follows
  a fixed template ([docs/ADDING_A_DETECTOR.md](ADDING_A_DETECTOR.md)).

## 7. Detection catalogue

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


## 8. Design deep-dive I — packet-time determinism

The engine's clock is the packet's capture timestamp, never `time.Now`, and it
is monotonic by construction: `now = max(now, packet.Timestamp)`. Every rate and
timing decision — flood windows, scan windows, dedup suppression, slow-attack
timers, beacon intervals, baseline intervals, incident windows — reads this
clock.

Consequences:

- **Determinism.** Replaying a pcap produces byte-for-byte the same alerts every
  time, which is what makes the scenario tests meaningful and the committed
  `demo/captures/` a faithful stand-in for live attacks. Scenario pcaps are
  generated with synthetic timestamps (never real time), so a test written today
  and run next year still asserts the same thing.
- **Robustness to a stepping clock.** WSL2's wall clock can jump backwards when
  the VM sleeps. A wall-clock engine would reopen closed windows or shrink open
  ones; the monotonic packet clock cannot, so detection is unaffected by the
  host clock. (This is precisely why the *live* demo still prefers a real
  machine — the artifact it removes is timing noise on the display, not
  detection correctness.)
- **Batching is free.** The live capture batches frames (TPACKET_V3 blocks, up
  to a 100 ms read timeout), so a packet can reach the dashboard up to ~100 ms
  late, but its *detection* uses the capture timestamp, so nothing shifts.

## 9. Design deep-dive II — spoofable vs. reliable attribution, and framing resistance

The central honesty of the system: **an IP source address is evidence only when
the sender had to receive a reply to get that far.** Every alert carries an
`attribution` of `reliable` or `spoofable`, assigned in
[internal/rules/attribution.go](../internal/rules/attribution.go) by rule kind
and protocol:

- **Reliable**: a signature on a TCP flow whose handshake completed; anything
  needing a reassembled application message (which needs a handshake);
  `stream_anomaly`; `slowloris` (connections held open); `beacon` (answered
  connections on a timer); `arp_spoof` (keyed on the *sender MAC* — the MAC is
  the identity, not the claimed IP); DNS tunnel/DGA over TCP.
- **Spoofable**: bare SYNs and other single packets; all UDP, ICMP, ARP-claimed
  IPs, other IP; `syn_flood`/`port_scan`/`host_sweep` (SYNs of handshakes that
  never completed); `udp_flood`/`dns_amplification`/`dns_spoof` (reflection
  *works because* the source is forged); `ttl_anomaly`/`frag_attack` (per-packet
  header fields); `baseline` (rates regardless of origin).

**Framing resistance.** Correlation
([internal/rules/correlate.go](../internal/rules/correlate.go)) builds incidents,
but a spoofable alert never *names an attacker*: a spoofed source Z adds to its
victim's score but is never credited as an attacker unless Z has a **reliable**
alert of its own against that victim. So a UDP flood forged to look like it comes
from Z cannot make the IDS accuse Z of an intrusion — verified by the
`spoofed_framing` scenario. A real attacker's SYN scan still counts as its own
recon once it earns a reliable alert. A table test, `TestAttributionClasses`,
checks *every* detector and every signature rule kind/category in `rules.conf`
against the attribution table, so the classification cannot silently drift.

This is what lets incidents be trustworthy: multi-stage, compromised-host and
callback incidents are assembled only from reliable attackers, over bounded
per-entity histories, and are logged once on creation and again only when the
stage set grows or severity rises.

## 10. Design deep-dive III — TCP reassembly and evasion

Application signatures are worthless if an attacker can split the payload across
TCP segments or IP fragments. Two layers address this:

- **TCP reassembly** (`internal/stream`) sits between the transport and
  application parsers and reassembles the flows on the application ports
  (21/53/80/443/8000/8080/8443, extensible with `-stream-ports`), handing the
  parser whole messages. It buffers only the message in progress per direction
  (HTTP head ≤16 KiB, DNS ≤64 KiB, FTP line ≤8 KiB, TLS first record ≤16 KiB)
  plus up to 16 out-of-order segments, and uses RFC 1982 serial arithmetic for
  sequence numbers. Overlapping segments carrying *different* data raise
  `overlap_conflict` (sid 1000501) — the classic reassembly-ambiguity evasion.
- **Flows open on data, not on SYN.** A SYN/SYN-ACK only writes into a fixed
  16384×4-way handshake table (~4 MB, allocated once, pointer-free); the flow is
  opened by the first segment with payload. So a spoofed SYN flood recycles
  table slots and allocates *nothing* — the `spoofed_syn_flood_no_stream_flows`
  scenario checks that 5,000 spoofed handshakes leave `flows_total` at 0. This
  is both a memory-safety property and an evasion-resistance property.
- **Fragments are tracked, not reassembled.** The fragment tracker keeps offset
  ranges (and the first fragment's headers), which is enough to detect
  overlapping fragments (teardrop), tiny fragments, oversized reassembled
  length (ping of death) and datagrams that never complete (fragment flood),
  without the memory cost of full reassembly.

The design is explicit about its limits (documented under *Known gaps*):
non-application ports are parsed per segment, bodies are skipped (so a
body-only overlap is not flagged), mid-stream pickups stay desynced until a
message boundary, and HTTP/2/WebSocket/CONNECT/FTPS fall back to per-segment
parsing. Stating these is part of the methodology — the tests assert the
boundary, not a capability we do not have.

## 11. Testing methodology

Five layers, each with a specific job (see [docs/SCENARIOS.md](SCENARIOS.md) and
[docs/ADDING_A_DETECTOR.md](ADDING_A_DETECTOR.md)):

1. **Unit tests** per package. `go test -race ./...` passes on all 13 packages
   with the race detector on.
2. **End-to-end scenarios.** **145** scenario captures under
   `testdata/scenarios/` run through `ids run -r … -no-tui` and are compared to
   an expected result. Every detector has at least one scenario that *fires* and
   a benign **look-alike** that must *not*, so a detector cannot pass by simply
   alerting on everything.
3. **Mutation checks.** For a detector under change we deliberately break the
   logic (flip a comparison, drop a condition), confirm a test or scenario
   fails, then restore the file exactly — evidence the test actually constrains
   the code.
4. **Fuzzing.** **12** fuzz targets across the parsers (lower/upper/app,
   including DNS-name decoding, overlong-UTF-8, JA3, inner-ICMP), the rule
   loader, the intel-feed loader, and the whole pipeline and stream stage
   (`FuzzPipeline`, `FuzzStream`). Each target runs at least 60 s in the validation pass, and this pass earned its keep: it surfaced **two** genuine parser defects on malformed input, both now fixed and kept as committed regression seeds. `FuzzDecodeOverlong` caught the overlong-UTF-8 canonicaliser turning an overlong-encoded UTF-16 surrogate (`f0 8d a5 80` -> U+D940) into the replacement character U+FFFD; the decoder now leaves invalid scalar values untouched. `FuzzParse` (lower) caught an IPv6 packet carrying two Fragment extension headers being left in an inconsistent fragment state (`IPFragmented` false while `FragPayloadLen` was non-zero); the extension-header walk now rejects a second Fragment header, as RFC 8200 requires. Neither defect fired on any benign or demo capture. With the fixes in place all 12 targets are clean, and the two failing inputs live under `testdata/fuzz/` so a regression would re-break the build.
5. **False-positive corpus.** Real benign captures are replayed and required to
   produce zero alerts and zero incidents (Section 12).

Credential handling is tested directly: parsers store `auth_basic=true` and
`<redacted>` rather than secrets, alert records carry no application fields, and
scenarios grep the log and stdout for planted passwords to prove none leak.

## 12. Results

Measured on this project's machine (WSL2 on Linux 6.6, amd64). Reproduce the
performance figures with `scripts/bench.sh` and `scripts/soak.sh`; both replay
the committed `demo/captures/` through the pipeline over a FIFO, so they need no
network and no privileges.

**Correctness gate** (all green): `gofmt` clean; `go build ./...`; `go vet
./...`; `staticcheck ./...` clean; `go test -race ./...` — 13/13 packages pass;
`make scenarios` — 145 scenarios pass.

**Coverage** (`go test -cover ./...`, per package):

| package | coverage |
|---|---|
| internal/parser/lower | 100.0% |
| internal/packet | 100.0% |
| internal/entropy | 100.0% |
| internal/rules | 96.8% |
| internal/parser/upper | 96.7% |
| internal/intel | 95.5% |
| internal/parser/app | 93.3% |
| internal/logging/tui | 92.7% |
| internal/stream | 92.3% |
| internal/logging | 84.1% |
| cmd/ids | 80.1% |
| internal/capture | 59.8% |
| cmd/capturedump | 47.5% |
| internal/testutil/pcapgen | n/a (test helper) |

The lower figures are the live-capture layer (`internal/capture`, hard to unit
test without hardware), the debug CLI (`cmd/capturedump`, a thin wrapper) and
the pcap-generation test helper (exercised through the scenario tests, not
measured directly). We noted these rather than chasing coverage in code that is
best exercised end-to-end.

**False-positive corpus** (benign traffic, replayed through `rules.conf`):

| capture | packets | alerts | incidents |
|---|---|---|---|
| eth0.pcap | 23,048 | 0 | 0 |
| lo.pcap | 1,014 | 0 | 0 |
| **total** | **24,062** | **0** | **0** |

**Throughput** (`scripts/bench.sh`, quiet machine):

| metric | value |
|---|---|
| corpus passes | 60 |
| packets processed | 583,380 |
| wall time | 2.06 s |
| throughput | ~283,000 pkt/s |
| pipeline line rate | ~25.7 Gbit/s (~3.2 GB/s) |
| peak RSS | ~49 MB |
| output | deterministic (90 alerts / 13 incidents per pass set) |

This is end-to-end pipeline throughput on FIFO-replayed captures (parse -> detect -> reassemble -> correlate -> log), measured without a NIC, so it reflects processing headroom rather than a live-capture ceiling; the figures were stable to within 0.2% across repeated runs.

**60-minute soak** (`scripts/soak.sh`, one long-lived process, mixed workload):

| metric | value |
|---|---|
| uptime | 3,709 s (~62 min) |
| packets processed | 811,705,209 |
| mean throughput | ~218,900 pkt/s |
| kernel / queue drops | 0 / 0 |
| table evictions | 0 |
| alerts / incidents | 345 / 13 |
| RSS post-warmup baseline | 50.2 MB |
| RSS peak / final | 54.6 / 52.7 MB |
| RSS growth (warmup -> final) | +2.5 MB over ~59 min |

Over an hour of sustained mixed traffic the resident set stays flat within a few megabytes and not one LRU table had to evict, evidence that the pipeline's per-flow and per-host state is bounded and does not leak under load.

**Demo verification.** All 30 committed captures in `demo/captures/` replay to
their expected alert or incident (`demo/replay.sh`: 30 passed, 0 failed),
including the two correlated-incident kill chains.

## 13. Known limitations

- Detection covers what the sensor can *see*: UDP scans are only seen through
  their closed ports, and a one-directional (asymmetric / single-side SPAN)
  capture sees no SYN-ACKs, so those flows are treated as mid-stream pickups.
- TCP reassembly covers the configured application ports and message headers,
  not bodies; a body-only overlap is not flagged, and HTTP/2, WebSocket, CONNECT
  tunnels and FTPS revert to per-segment parsing.
- The statistical baseline is deliberately conservative (anomalous intervals
  never train it, updates are clamped), which resists a fast poisoning attack
  but not an infinitely slow one (the "boiling frog").
- Single-threaded by design: correctness and determinism over multi-core
  throughput. The measured single-core rate is well above the traffic these
  demos generate, but a saturated 10 GbE tap would need sharding.
- Live capture requires Ethernet link type and `cap_net_raw`/`cap_net_admin`;
  the Linux `any` device and macOS loopback are rejected at startup.

## 14. Module ownership

_Fill in each module's owner (the team lead has the assignment). Keep in sync
with the same table in the README._

| # | Module | Package | Owner |
|---|---|---|---|
| 1 | Packet capture | `internal/capture` | _TBD_ |
| 2 | Ethernet/IP parsing | `internal/parser/lower` | _TBD_ |
| 3 | TCP/UDP/ICMP parsing | `internal/parser/upper` | _TBD_ |
| 4 | HTTP/DNS/FTP parsing | `internal/parser/app` | _TBD_ |
| 5 | Rule engine + correlation | `internal/rules`, `internal/stream`, `internal/intel` | _TBD_ |
| 6 | Dashboard + logging | `internal/logging` | _TBD_ |

## 15. Per-member contributions

_One short paragraph per member; fill in from the team's own record._

- _Member A — …_
- _Member B — …_
- _Member C — …_
- _Member D — …_

## 16. References

- Roesch, M. *Snort — Lightweight Intrusion Detection for Networks.* LISA 1999
  (the rule-language lineage).
- Ptacek, T. & Newsham, T. *Insertion, Evasion, and Denial of Service: Eluding
  Network Intrusion Detection.* 1998 (fragmentation/segment-overlap evasion).
- Postel, J. *RFC 791/792/793* (IP/ICMP/TCP); Elz, R. & Bush, R. *RFC 1982*
  (serial-number arithmetic).
- gopacket / libpcap (packet capture and decoding).
- Salesforce. *JA3 — TLS client fingerprinting.*
- Project docs: [ARCHITECTURE.md](ARCHITECTURE.md), [RULES.md](RULES.md),
  [SCENARIOS.md](SCENARIOS.md), [ADDING_A_DETECTOR.md](ADDING_A_DETECTOR.md),
  [DEMO.md](DEMO.md).
