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
   file: wait                stream.Process  TCP reassembly on app ports
                             app.Parse     HTTP, DNS, FTP, TLS ClientHello
                             engine.Process  rules, handshakes, dedup
                               |   correlate    alerts -> incidents
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
  The field comments name the owner (1 capture, 2 lower, 3 upper, the
  stream stage, 4 app). The stream stage may also write the `http_*`
  entries of `AppFields` before stage 4 adds its own.
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

**Stateless parsers, one bounded stream stage.** Every parser decodes one
frame on its own; nothing defragments IP. Between the transport and
application parsers, [internal/stream](../internal/stream/stream.go)
reassembles TCP on the application ports (21, 53, 80, 8000, 8080, 443,
8443; `-stream-ports`) and hands the parser whole messages in `AppData`.
It buffers only the message in progress in each direction, never
bodies: an HTTP head up to 16 KiB, a DNS message up to 64 KiB, an FTP
line up to 8 KiB, a TLS first record up to 16 KiB, plus up to 16
out-of-order segments. Sequence numbers use RFC 1982 serial arithmetic.
Flows end on FIN from both sides, RST or 2 minutes idle; past 64 MiB in
total (`-stream-max-mem`), the least recently used flows are evicted.
A flow picked up mid-stream, or one that lost bytes, starts desynced and
is parsed one segment at a time (as before reassembly) until a segment
starts a message. Other state lives in the rule engine, in bounded
tables.

**Flows open on data, not on SYN.** A SYN or SYN-ACK only writes an entry
in a fixed handshake table ([handshake.go](../internal/stream/handshake.go):
16384 sets of 4 ways, about 4 MB allocated once, no pointers) holding the
client side and both initial sequence numbers. The flow is opened by the
first segment with payload, which takes those numbers and starts in sync.
A spoofed SYN flood therefore fills and recycles table slots (a new SYN
takes a free or stale way, or the oldest) and allocates nothing: the
`spoofed_syn_flood_no_stream_flows` scenario checks that 5000 spoofed
handshakes leave `flows_total` at 0. A connection whose slot was
recycled before its first data is opened the way a mid-stream pickup is.

**Single-threaded parse and engine.** One goroutine parses and matches
every packet, in capture order. The handshake tracker and the dedup
windows need packets in order and would need locks otherwise. The whole
path, with the 74 rules of the default rules.conf, measured about 5.5 s
for a million spoofed flood SYNs from a pcap and 3.3 s for a million
mixed packets carrying 100k HTTP requests (the web rules' regexes and
the DNS query table are about 0.3 s each of that), so one core is not
the bottleneck for this project. Capture and log writing are
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
ttl_anomaly, tcp_flows, fragments, frag_flood, arp_bindings,
arp_requests, arp_spoof, udp_flood, udp_flows, icmp_flood, icmp_peers,
echo_requests, icmp_tunnel, slow_flows, slowloris, the DNS tables, beacon,
beacon_conns, baseline_hosts, incident_entities and incidents) holds at
most 50,000 keys (baseline_hosts and incident_entities at most 10,000,
each baseline host with a 512-byte bitmap, each entity with up to 64
contributions). At the cap,
the least recently seen key is evicted and counted in the stats
record (`evictions`), so memory stays flat under attack. An evicted
handshake counts as incomplete, which is right for a flood. In the
stress test (1,000,000 SYNs from distinct spoofed sources, replayed with
`ids run -r` and the default rules.conf), peak RSS is 176 MB. Handshake,
syn_flood and ttl_anomaly each evict 950,000 keys, port_scan and
host_sweep sit at the 50,000 cap (every timed-out handshake is also a
probe), and the by_dst alert still fires. The same capture peaked at
104 MB before the scan detectors, and 150 MB before ttl_anomaly, which
keeps an entry for every external source it sees. The stream stage
(port 80 is reassembled) raises it to about 350 MB: every SYN opens a
stream flow, the 64 MiB budget holds about 106,000 of them and evicts
the rest, and the garbage collector's headroom roughly doubles that
live heap. `-stream-max-mem` trades flood RSS against how many real
flows survive a flood. Replay throughput on that capture drops from
about 220,000 to 160,000 packets/s (flow allocation, the flow map, and
GC scanning of the flow table); on a mixed 1,000,000-packet capture it
goes from about 400,000 to 345,000.

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

**Regexes are RE2.** `regex:` compiles with Go's regexp (RE2), which
runs in time linear in the input, so a crafted request cannot make a
rule backtrack for seconds (the PCRE ReDoS problem). The price is no
backreferences and no lookaround; the web rules are written without
them. Each evaluation reads at most the first 16 KiB of its field or
data, and the literal options of a rule (`content`, `app_content`,
`app_domain`, `app_field`) are checked first, so the regex runs only on
packets that already look relevant.

**One DNS query table for all DNS detectors.** Spoofing and amplification
both depend on whether a response was asked for, so the engine keeps one
table of outstanding questions per transaction (client address and port,
server, id), fed by every query including whitelisted ones, and every
response is classified against it before any rule runs. A forged answer
must match the port and id to be *matched*; one that matches port and id
but not the question is a *mismatch*. `id_race` additionally needs a
question for the same name waiting at the same server, which is what a
Kaminsky race targets and what a reflection victim never has.

**Domains by the Public Suffix List.** dns_tunnel groups queries by
registered domain (eTLD+1, golang.org/x/net/publicsuffix). "The last two
labels" would make `co.uk` and `github.io` single domains, so a user
browsing many British sites or GitHub Pages projects would look like one
domain with hundreds of random subdomains (the
`dns_cdn_many_subdomains_couk` scenario). The list includes its private
section, so each `*.cloudfront.net` distribution is its own domain too.

**Threat-intel feeds are loaded with the rules.** A `feed` line in the
rules file names a file of indicators, read whenever the rules are, so
refreshing a feed is the same SIGHUP as editing a rule, and a bad feed
file keeps the old rules like a bad rule does. IP feeds are a sorted
range table searched with a binary search; domain feeds a set checked
for the name and each parent (`a.b.c`, `b.c`), so a lookup is a few map
probes whatever the feed size. Private and reserved ranges are rejected
line by line: a feed entry of `10.0.0.0/8` is always a mistake and would
flag the whole network. `make feeds` fetches public feeds but the data is
never committed: it changes hourly and belongs to its providers.

**Beacons by median interval.** detect:beacon judges only connection
starts, so a long-lived connection's keepalives count once, and it takes
the median of the last 31 intervals rather than the mean: one sleep of
the laptop or one burst of retries moves a mean anywhere, but moves the
median by at most one position. The 2x band counts a skipped beat as
regular, since beacons miss rounds when the network is down. A key
alerts once per periodic streak: a 5-minute beacon would otherwise raise
an alert on every beat, past the 60 s dedup window.

**Baselines with absolute deviation.** detect:baseline scores each
interval as (value − EWMA mean) / EWMA absolute deviation, with a
per-metric floor. The variance, the usual choice, squares each deviation,
so one burst dominates it for many intervals and hides the next;
traffic volume is heavy-tailed, with bursts the rule. The absolute
deviation grows in proportion to the burst, needs no square root and is
in the metric's own units. Distinct destinations are counted in fixed
bitmaps (linear counting), so a host that contacts a million addresses
costs no more memory than one that contacts ten. An anomalous interval
never updates the baseline, and every update is clamped to `max_step`,
which together make it hard to teach the baseline an attack; see the
boiling frog under Known gaps for what they cannot stop.

<a id="attribution"></a>**Attribution.** An IP source address is only
evidence when the sender had to receive a reply to get that far. Every
alert carries `Details["attribution"]`, set by the engine
([internal/rules/attribution.go](../internal/rules/attribution.go)):

| alert | attribution | why |
|---|---|---|
| signature rule on TCP, flow whose handshake the tracker saw complete | reliable | the source answered the SYN-ACK |
| signature rule on TCP with `app_proto`, `app_field`, `app_content`, `app_domain`, `app_reason`, `domain_feed`, `ja3_feed` or another per-message option | reliable | the application layer needs a reassembled stream, which needs a handshake; true even for a flow picked up mid-capture |
| signature rule with `stream_anomaly` | reliable | the stream layer tracks both directions |
| signature rule on TCP otherwise (a SYN, a flow begun before the capture started, `flags` probes, `ip_feed` on a SYN) | spoofable | nothing proves the source saw a reply |
| signature rule on UDP, ICMP, other IP, ARP | spoofable | one forged packet is enough |
| `slowloris` | reliable | connections held open through the stream layer |
| `beacon` | reliable | repeated answered connections on a timer; periodic forged packets cannot fake it usefully |
| `arp_spoof` | reliable | keyed on the sender MAC: the MAC is the identity (the incident entity is the MAC, not the claimed IP) |
| `dns_tunnel`, `dns_nxdomain_burst` over TCP | reliable | the client's own queries over a completed handshake |
| `dns_tunnel`, `dns_nxdomain_burst` over UDP | spoofable | the client address of a UDP query can be forged |
| `syn_flood`, `port_scan`, `host_sweep` | spoofable | SYNs of handshakes that never completed |
| `ping_sweep`, `icmp_flood`, `icmp_tunnel` | spoofable | ICMP |
| `udp_flood`, `dns_amplification`, `dns_spoof` | spoofable | UDP (reflection works precisely because the source is forged) |
| `ttl_anomaly`, `frag_attack` | spoofable | per-packet IP header properties |
| `baseline` | spoofable | rates of packets whatever their origin |
| incidents | reliable | built only from reliable attackers (below) |

A table test (`TestAttributionClasses`) checks every detector and every
signature rule kind and category in rules.conf against this table.

**Correlation.** [internal/rules/correlate.go](../internal/rules/correlate.go)
runs in the pipeline goroutine, inside the engine: every new alert (not
summaries, not incidents) is added to the bounded history of its source
(attacker role) and destination (victim role), with its time, sid, stage,
severity and peer; `detect:incident` rules then look at the histories,
and `callback` rules also at every new SYN from the handshake tracker.
Spoofable alerts never name an attacker: a spoofed source Z adds to its
victim's score, but an incident's attacker needs a reliable alert of its
own against that victim, so a UDP flood forged from Z cannot frame Z (the
`spoofed_framing` scenario). A real attacker's SYN scan still counts as
its recon once it has a reliable alert against the victim. An incident is
logged when created and updated only when its stage set grows or its
severity rises, so a long attack gives a handful of records, not one per
alert. RULES.md has the kinds, windows and score.

The correlator sees what the engine emits, so dedup applies first: a
second SQL injection within 60 s of the first is a `summary`, not a new
contribution. That loses nothing a stage set needs (the first alert of
each sid is always there) and keeps a flood of repeats from filling the
64-slot histories.

**WSL2 limitations.** The development machine is WSL2, where DNS goes to a
proxy on `lo` rather than `eth0`, the clock sometimes steps backwards, and
Hyper-V coalescing produces oversized frames and bad inbound checksums.
Each of these looked like a bug at first; the decisions above are how the
IDS stays correct regardless. Linux `lo` is Ethernet-framed, so it can be
captured; the `any` device and macOS loopback cannot.

## Known gaps

**What TCP reassembly cannot see.** The stream stage closed the gap of
messages split across segments (a DNS length prefix sent apart from its
message, HTTP heads and TLS ClientHellos over several segments), but:

- Only the application ports are reassembled; HTTP on port 8888 is still
  parsed per segment. `-stream-ports` adds ports.
- Bodies are skipped, not buffered, so a conflicting retransmission of
  body bytes, or of any bytes older than the last delivered message, is
  not detected as `overlap_conflict`.
- A message that never completes (a slowloris head, a connection reset
  mid-message) is never parsed; slowloris sees it through the HTTP state
  instead.
- A flow picked up mid-stream that never reaches a message boundary (a
  long download, a TLS session after its handshake) stays per segment and
  is invisible to `detect:slowloris`.
- A flood of new flows past `-stream-max-mem` evicts real ones, which then
  continue desynced. Each flow is charged its own size and map slot (631
  bytes on amd64) plus its buffers, so the 64 MiB default holds at most
  about 106,000 flows.
- HTTP/2, WebSocket (after a 101), CONNECT tunnels and FTP after AUTH TLS
  go back to per-segment parsing.

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
count as anomalous (tcp_flows remembers them), because a load balancer,
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

**DNS the IDS cannot read.** DNS over HTTPS and over TLS are encrypted:
the DNS detectors see nothing of them, which is why rules 1000111
(DoH by SNI) and 1000112 (TCP 853) flag their use as policy events. DoH
to a server not in `$DOH_SERVERS`, or with Encrypted Client Hello hiding
the SNI, is invisible. A sensor that sees only responses (asymmetric
routing) finds every response unsolicited, and a tunnel slower than
`count` subdomains per `seconds` is not detected.

**UDP floods that get answers.** A flood at a service that answers every
datagram (an open DNS or echo port) is not a udp_flood by design; the
reply ratio is what keeps QUIC and VoIP quiet. Reflection floods arrive
from the reflectors' service ports and are covered by a plain rule on
`$REFLECTOR_PORTS` (1000013) instead. With `track:by_dst`, a victim that
also has an unrelated conversation with some of the spoofed addresses
counts those packets as replies.

**The boiling frog.** Any baseline that adapts can be taught. An attacker
who raises traffic by a little less than `threshold` deviations per
interval never produces an anomalous interval, so the baseline follows
the ramp to any level; the deviation, which grows with each step, makes
the next step larger still. Freezing on anomalies stops only a jump, and
`max_step` bounds each update to 20% of the current value (or of the
floor), which slows a ramp but does not stop one: from 1 to 50 packets/s
takes about fifteen intervals. A lasting change, legitimate or not, is
also learned after 60 anomalous intervals in a row, after it alerted. What stops the frog is
a second, slower reference (last week's baseline) or a fixed ceiling,
neither of which is implemented; the fixed-threshold detectors (udp_flood,
syn_flood) are that ceiling for the attacks they cover. Learning also
trusts its first `learn_intervals`: an attack already running when the
IDS starts becomes the baseline (`baseline_learning_no_alert`).

**Baseline intervals close on packets.** A baseline interval ends when
the next packet after it arrives, since the engine clock is packet time.
A link that goes completely silent never closes an interval, so
`drop:packets` fires only once traffic, even a trickle, resumes.

## Testing layers

| layer | where | what it proves |
|---|---|---|
| unit tests | `internal/*/..._test.go` | each parser and engine table |
| scenarios | [testdata/scenarios](../testdata/scenarios), [SCENARIOS.md](SCENARIOS.md) | end-to-end alerts through `run()` |
| fuzz | `FuzzPipeline` in cmd/ids | no panics, well-formed alerts on any input |
| edge cases | `TestPcapEdgeCases`, `TestSpoofedFloodTableCap` | damaged pcaps, time jumps, the table cap |

`make test`, `make scenarios` and `make fuzz` run them; CI runs all of them
with `-race`.
