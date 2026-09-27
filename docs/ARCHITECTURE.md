# Architecture

## Pipeline

```
 capture goroutine            pipeline goroutine (one)                     writer goroutine
 -----------------            ------------------------                     ----------------
 libpcap (iface / file)
   |  copy frame into a
   |  new ParsedPacket
   v
 [queue: chan, 10000] ---> lower.Parse   Ethernet, VLAN, IPv4/IPv6, ARP
   live: drop when full      upper.Parse   TCP, UDP, ICMP/ICMPv6, checksums
   file: wait                app.Parse     HTTP, DNS, FTP, TLS ClientHello
                             engine.Process  rules, handshakes, dedup
                               |
                               +--> alerts --> [chan] --> JSON Lines log (rotating)
                               +--> alerts --> dashboard (or stdout with -no-tui)
                               +--> traffic counters (dashboard, stats records)
```

The entry point is `run()` in [cmd/ids/run.go](../cmd/ids/run.go): it
loads the rules, opens the capture, opens the log and then starts the
three goroutines. On shutdown the capture closes its channel. The
pipeline then calls `engine.Flush` (so pending summaries are logged),
writes a final stats record and closes the log.

## The ParsedPacket contract

[internal/packet](../internal/packet/packet.go) defines `ParsedPacket`, the
only thing stages share.

- Each field is written by exactly one stage and read only by later ones.
  The field comments name the owner (1 capture, 2 lower, 3 upper, 4 app).
- `RawData` is a copy owned by the packet, never a buffer libpcap reuses,
  and no stage modifies it.
- A stage never rejects a packet. It fills in what it could decode and
  records problems with `AddError` (for `ParseErrors`) or `AddAppReason`
  (for `malformed` / `suspicious` reasons). Later stages check the offsets
  (`L3Offset`, `L4Offset`, `-1` when unknown) before reading.
- `internal/packet` imports no other internal package, and a change to the
  struct is a change to every module.
- `FragPayloadLen` (stage 2) is the number of bytes a fragment carries of
  its datagram, from the length fields rather than the captured bytes, so
  a fragment covers `[FragOffset, FragOffset+FragPayloadLen)`. The
  fragment detectors compare these ranges; nothing reassembles.
- For an ICMP Echo Request or Reply whose 8-byte header was captured,
  stage 3 sets `HasICMPEcho`, `ICMPEchoID` and `ICMPEchoSeq`, and
  `PayloadOffset` points past the identifier and sequence number, so
  `Payload()` is the echo data (what `ping -s` sizes and `dsize`
  compares). Every other ICMP message's payload starts after the 4-byte
  type, code and checksum.

## Design decisions

**Stateless parsers.** Every parser decodes one frame on its own: there is
no TCP reassembly, flow table or IP defragmentation. That keeps parsing
bounded and impossible to exhaust with state, at the price of missing
anything split across segments (see [Known gaps](#known-gaps)). State
lives in the rule engine, in bounded tables.

**Single-threaded parse and engine.** One goroutine parses and matches
every packet, in capture order. The handshake tracker and the dedup
windows need packets in order and would need locks otherwise. The whole
path measured about 2.7 s for a million flood SYNs from a pcap, so one
core is not the bottleneck for this project. Capture and log writing are
the only other goroutines, joined by channels.

**Packet-time clock.** The engine's clock is the packet timestamp, never
`time.Now`, and it never goes backwards: `now = max(now, p.Timestamp)`.
Replaying a pcap gives the same alerts every time. A capture clock that
steps back (WSL2 does this) can neither reopen a closed window nor shrink
an open one.

**Checksum policy.** Transport checksums are verified and reported
(`L4ChecksumStatus`), but nothing alerts on them and the handshake
tracker ignores them. With checksum offload, every packet the capturing
host sends has a checksum the NIC has not filled in yet (12,732 of 27,908
frames in the 10-minute eth0 recording), and receive offload can merge
inbound segments without fixing theirs.

**GRO and oversized frames.** GRO/TSO hands libpcap merged frames of up to
64 KB, so the default snaplen is 262144 and an IP length over 1500 is not
malformed. Such frames keep their checksum unchecked, because it never
covered the merged bytes. Rules see one large payload, which only helps
content matching.

**Credential redaction.** Parsers never store credentials. The HTTP
`Authorization` header only sets `auth_basic=true`, and the FTP `PASS`
argument is stored as `<redacted>`. Alert records never include app fields
at all, and parse errors never quote packet bytes. The scenarios check the
log and stdout for the planted passwords; the parser unit tests check the
redaction itself.

**Bounded tables.** Every engine table (dedup, handshakes,
detection_filter, syn_flood, port_scan, host_sweep, ping_sweep,
ttl_anomaly, ttl_flows, fragments, frag_flood, arp_bindings,
arp_requests, arp_spoof, udp_flood, udp_flows, icmp_flood, icmp_peers,
echo_requests and icmp_tunnel) holds at most 50,000 keys. At the
cap, the least recently seen key is evicted and counted in the stats
record (`evictions`), so memory stays flat under attack. An evicted
handshake counts as incomplete, which is right for a flood. In the
stress test (1,000,000 SYNs from distinct spoofed sources, replayed with
`ids run -r` and the default rules.conf), peak RSS is 176 MB. Handshake,
syn_flood and ttl_anomaly each evict 950,000 keys, port_scan and
host_sweep sit at the 50,000 cap (every timed-out handshake is also a
probe), and the by_dst alert still fires. The same capture peaked at
104 MB before the scan detectors, and 150 MB before ttl_anomaly, which
keeps an entry for every external source it sees.

**by_dst SYN-flood tracking.** A spoofed flood uses a new source for every
SYN, so no source ever reaches the threshold. `track:by_dst` counts failed
handshakes per server, and `min_incomplete_ratio` (default 0.8) keeps a
busy server quiet as long as most of its handshakes complete. The
completions window keeps only the `count*(1-r)/r + 2` entries that can
change the ratio decision. That bounds it at 27 per server for the default
rule.

**Scan or flood.** Both start as incomplete handshakes. syn_flood
additionally requires the incompletes to hit at most
`max_distinct_ports` (default 5) ports; port_scan requires
`distinct_ports` (20) of them. So a flood of one port fires only
syn_flood, and a SYN scan of 1000 ports only port_scan
(`scan_is_not_flood`, `flood_is_not_scan`; chrissanders' synscan.pcapng
fires port_scan and not syn_flood).

**What a probe is.** The scan detectors count probes, not packets or
connections. A SYN is judged by the handshake's outcome, not when it is
sent: refused, unanswered or reset by the prober after the SYN-ACK is a
probe; a completed handshake is not. So a browser opening connections to
40 servers is not a host sweep, at the cost of counting a SYN probe only
when its handshake ends (up to the handshake timeout for filtered
ports). FIN-only, NULL and Xmas packets are probes on sight, since no
stack sends them in a working connection, but FIN/ACK and RST are not:
they are what connections that started before the IDS look like. A UDP
datagram is never a probe by itself (clients talk to many DNS and NTP
servers); the target's ICMP port unreachable is, credited to the host
that sent the quoted datagram, and only when the ICMP goes back to that
host. The quoted header is decoded by `upper.ParseICMPInner`, a
bounds-checked, fuzzed function, into the `ICMPInner*` fields of
`ParsedPacket`. port_scan counts distinct ports per source over any
hosts, and host_sweep distinct hosts per (source, port), so a sweep of
port 22 raises host_sweep and not port_scan.

**ARP bindings are learned from ARP only.** The arp_bindings table maps
an IPv4 address to the MAC that last claimed it as ARP sender. IP traffic
is never used: the Ethernet source of a packet from an off-link address
is the router's MAC. Senders of `0.0.0.0` (RFC 5227 probes) and invalid
MACs teach nothing, and `arpbind` addresses are never learned, so a
static binding cannot be overwritten by traffic. arp_requests remembers
(requester, target) for 5 s so a reply can be checked against it. Both
tables are shared by all arp_spoof rules and fed by every ARP packet,
whitelisted or not; arp_spoof holds each rule's own windows (flip_flop
returns, unsolicited replies, gratuitous announcements, addresses per
MAC).

**Fragments are tracked, not reassembled.** The fragment tracker keeps
only the byte ranges of each datagram (at most 64, for 30 s after its
first fragment), which is enough to see overlaps and datagrams that never
complete without buffering any payload. A datagram with more than 64
fragments is dropped from tracking and counted in `FragmentsOverLimit`
in the stats record; no legitimate sender needs that many. Exact
duplicates are ignored, since retransmitted or duplicated fragments are
normal. IPv4 fragments with a bad header checksum are skipped: the
target drops them too.

**TTL distance, not TTL.** ttl_anomaly compares hop distances (initial TTL
bucket minus observed TTL), so hosts with different default TTLs behind
one NAT address look the same, and only sources outside `$HOME_NET` are
tracked by default, where spoofing matters and local TTLs vary least.

**Rate windows in sub-buckets.** udp_flood and icmp_flood count per
address in a ring of 10 sub-buckets of `seconds`/10 (`rateCounter`), not
a timestamp per packet, so a flood of 60,000 packets costs the same
memory as one of 60. The sum covers the last 90 to 100% of the window,
and a threshold can be crossed up to one sub-bucket late. A key idle for
a whole window resets. The same counter keeps a few extra series (bytes,
replies) and the most frequent tag (destination port, ICMP type and
code) for the alert.

**A flood is traffic that is not answered.** Rate alone cannot tell a
UDP flood from a QUIC download or a call, so udp_flood also counts
replies and fires only when at most `max_reply_ratio` (2%) of the packets
got one. by_src asks whether the sender's own flows are answered; by_dst
asks whether the victim sends anything back to its senders, which also
works when every source is spoofed. The recent flows and (source,
victim) pairs are kept in `recentSet`s (udp_flows) that expire with the
window. Traffic from a host to itself uses the flow test for both
tracks, or every packet would answer itself. ICMP port unreachables are
not replies. icmp_flood kind:echo does not use replies: an answered
ping flood still costs the victim.

**Echo requests are remembered for replies.** kind:unsolicited_reply
needs to know which Echo Replies answer a request. echo_requests keeps
(requester, responder, identifier, sequence) for 10 s after the request,
with a wildcard responder when the request went to a broadcast or
multicast address, so every member of a group can answer. It is fed by
every Echo Request, whitelisted or not, and only while such a rule is
loaded.

**Tunnel payloads by shape, not content.** icmp_tunnel keeps only the
size and Shannon entropy (package `entropy`) of the last `count`
non-standard payloads per (client, server), never the bytes. Standard
ping payloads (Linux/BSD counting, Windows letters, zeros, empty) are
skipped before they enter the window, so a monitoring system pinging
all day adds nothing. A tunnel shows either many sizes (interactive
data) or random-looking bytes (compressed or encrypted data); `ping -p`
has one size and low entropy.

**WSL2 limitations.** The development machine is WSL2, where DNS goes to a
proxy on `lo` rather than `eth0`, the clock sometimes steps backwards, and
Hyper-V coalescing produces oversized frames and bad inbound checksums.
Each of these looked like a bug at first; the decisions above are how the
IDS stays correct regardless. Linux `lo` is Ethernet-framed, so it can be
captured; the `any` device and macOS loopback cannot.

## Known gaps

**DNS over TCP split across segments.** Without TCP reassembly, the DNS
parser sees each segment alone. When a client or server writes the 2-byte
length prefix and the message separately, or a boundary splits the prefix
1+1, the segment holding the message does not start with its length. Such
a segment does not frame cleanly and is classed as unknown traffic, not
malformed DNS (it used to raise a false `Malformed DNS message` alert on
tcpdump's `dns_tcp.pcap`). The price is that the message is not decoded at
all: in chrissanders' `dns_axfr.pcapng` the AXFR query arrives as a
2-byte prefix segment followed by the message, so a rule on
`app_field:qtype_name=AXFR` misses it. Likewise, a malformed message is
reported only when its length prefix matches the segment, since the start
of a longer message could be misaligned. TCP stream reassembly, planned
for the next step, closes this gap.

**Scans the engine cannot see.** A UDP probe to an open or filtered port
gets no ICMP answer and is not counted, so a UDP scan is only seen through
its closed ports. A capture that holds only one direction of traffic
(asymmetric routing, a SPAN port on one side) sees no SYN-ACKs: every
handshake times out and counts as a SYN probe, so busy clients look like
scanners. Such sensors should whitelist their clients or disable
port_scan and host_sweep. A slow scan below `distinct_ports` per
`seconds` is not detected.

**TTL anomalies after a route change.** A source whose path lengthens by
more than `max_hop_diff` hops for good looks spoofed until the new
distance collects `min_samples` samples; with the default rule a busy
source raises one alert, then settles. ttl_anomaly cannot tell a spoofer
that guesses the right TTL from the real host.

**Load balancers and anycast over UDP.** Completed TCP connections never
count as anomalous (ttl_flows remembers them), because a load balancer,
anycast address or per-flow ECMP path gives each connection its own
distance. UDP and ICMP have no handshake to prove the source is real, so
an anycast DNS resolver or CDN answering over UDP from different
distances can still trip ttl_anomaly; the default rule is severity low
for that reason.

**ARP on a switched network.** A switch forwards unicast ARP only to its
destination, so the IDS sees broadcast requests, gratuitous ARP and ARP
to or from its own host. Poisoning aimed at another host with unicast
replies is invisible unless the IDS is on a mirror port. The first MAC
heard for an address is trusted: a spoofer already present when the IDS
starts is learned as the owner, and only `arpbind` or the real host
answering (flip_flop, mac_change) exposes it. A proxy-ARP router
legitimately answers for many addresses and needs a pass rule
(`multi_ip`).

**No reassembly behind fragments.** Rules match fragments one at a time:
content split across fragments is missed, and `tcp`/`udp` rules never
see non-first fragments. The frag_attack detectors flag the known abuse
patterns but do not reassemble.

**Fragmented pings.** `dsize` sees one frame at a time, so an Echo
Request fragmented on the wire has at most the first fragment's share
of the payload (1472 bytes on a 1500-byte MTU). Rule 1000902
(`dsize:>1472`) therefore fires only on unfragmented oversized pings
(jumbo frames, `lo`, GRO-merged frames); a fragmented ping of death is
left to the frag_attack rules. Fragmented echo payloads are not seen by
icmp_tunnel either, beyond the first fragment.

**Monitoring hosts and ping_sweep.** A monitoring system that pings 15
or more hosts within 30 s trips ping_sweep (1000403), as in the
`icmp_monitoring_pings` scenario. Its pings are standard and answered,
so icmp_flood and icmp_tunnel stay quiet; whitelist the monitoring host
for ping_sweep.

**UDP floods that get answers.** A flood at a service that answers every
datagram (an open DNS or echo port) is not a udp_flood by design; the
reply ratio is what keeps QUIC and VoIP quiet. Reflection floods arrive
from the reflectors' service ports and are covered by a plain rule on
`$REFLECTOR_PORTS` (1000013) instead. With `track:by_dst`, a victim that
also has an unrelated conversation with some of the spoofed addresses
counts those packets as replies.

## Testing layers

| layer | where | what it proves |
|---|---|---|
| unit tests | `internal/*/..._test.go` | each parser and engine table |
| scenarios | [testdata/scenarios](../testdata/scenarios), [SCENARIOS.md](SCENARIOS.md) | end-to-end alerts through `run()` |
| fuzz | `FuzzPipeline` in cmd/ids | no panics, well-formed alerts on any input |
| edge cases | `TestPcapEdgeCases`, `TestSpoofedFloodTableCap` | damaged pcaps, time jumps, the table cap |

`make test`, `make scenarios` and `make fuzz` run them; CI runs all of them
with `-race`.
