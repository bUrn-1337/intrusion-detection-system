# Rule language

This is the reference for `rules.conf` and any file passed with `-rules`.
The parser is [internal/rules/parse.go](../internal/rules/parse.go); the
starter rules are in [rules.conf](../rules.conf).

```
action proto src_addr src_port direction dst_addr dst_port (options)
```

One rule per line. Blank lines and lines starting with `#` are ignored. A
rule file with any error is rejected as a whole: every problem is reported
as `file:line: message` (unknown option, bad value, missing `msg` or `sid`,
duplicate `sid`, invalid address or port, option not valid for the
protocol), and nothing starts. On a reload (`kill -HUP` or the `r` key) a
bad file leaves the old rules active.

## Header

### action

| value | meaning |
|---|---|
| `alert` | report a match |
| `pass` | silence the packet. Pass rules are checked first; a packet that matches one is not checked against any alert rule |

```
pass udp 10.0.0.53 53 -> any any (msg:"Trusted resolver"; sid:1000900;)
```

### proto

| value | packets |
|---|---|
| `ip` | every IPv4 and IPv6 packet, whatever the transport |
| `tcp`, `udp` | a fully decoded TCP or UDP header. Non-first fragments carry none, so only `ip` rules see them |
| `icmp` | ICMP and ICMPv6 |
| `arp` | ARP; the sender and target IPs are the src and dst addresses |

```
alert arp any any -> 192.168.1.1 any (msg:"ARP for the gateway"; sid:1000901;)
```

### Addresses

`any`, an IPv4 or IPv6 address, a CIDR prefix, or a list `[a,b,...]` of
those. `!` negates the whole spec (`!a`, `![a,b]`) or one list item
(`[10.0.0.0/8,!10.0.0.1]`). A list with only negated items matches
everything else.

```
alert tcp [10.0.0.0/8,!10.0.0.1] any -> 2001:db8::/32 any (msg:"Internal to lab v6"; sid:1000902;)
alert ip !192.168.0.0/16 any -> any any (msg:"Non-local source"; sid:1000903;)
```

### Ports

`any`, `N`, `N:M`, `N:` (N and up), `:M` (up to M), or a list of those,
with the same negation forms as addresses. Ports must be `any` for `ip`,
`icmp` and `arp` rules.

```
alert tcp any 1024: -> any [21,23,3389,5900:5910] (msg:"Cleartext admin port"; sid:1000904;)
alert udp any any -> any !53 (msg:"UDP not to DNS"; sid:1000905;)
```

### direction

`->` matches src to dst. `<>` matches either way round.

```
alert tcp 10.0.0.5 any <> any 22 (msg:"SSH to or from the build host"; sid:1000906;)
```

### Variables

`var NAME value` defines `$NAME`, usable in any address or port field. The
value is one address or port spec (no spaces) and may use other variables.
Definitions can come anywhere in the file, before or after their use.

```
var HOME_NET [10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8,::1,fc00::/7,fe80::/10]
var EXTERNAL_NET !$HOME_NET
var WEB_PORTS [80,443,8080]
alert tcp $EXTERNAL_NET any -> $HOME_NET $WEB_PORTS (msg:"Inbound web"; sid:1000921;)
alert tcp any any -> [$HOME_NET,!10.0.0.1] 22 (msg:"SSH to home except the jump host"; sid:1000922;)
```

- `$NAME` as a whole field takes the value; `!$NAME` negates it (a value
  that is already negated loses its `!`, so `!$EXTERNAL_NET` is
  `$HOME_NET`).
- `$NAME` or `!$NAME` as a list item splices the value's items into the
  list. Only a value without `!` and other than `any` can be spliced.
- An address variable in a port field, or the reverse, is an error.
- An undefined variable, a second `var` with the same name and a reference
  cycle (including a variable that refers to itself) are load errors,
  reported as `file:line`.

A value that is neither an address nor a port spec is a **name list**: one
domain name or `[a,b,...]` of them (letters, digits, `-` and `_`, labels
of 1 to 63 characters, at least one letter, at most 1000 names). Names are
lowercased and a trailing dot is dropped. A name list is used by
`app_domain` and by the `allow` option of `detect:dns_tunnel`, never in
an address or port field (`$N holds names, not addresses`). Name lists
can splice other name lists but cannot be negated.

```
var DOH_SERVERS [dns.google,cloudflare-dns.com,one.one.one.one]
alert tcp any any -> any 443 (msg:"DoH"; app_proto:tls; app_domain:sni,$DOH_SERVERS; sid:1000111;)
```

Name lists are variables rather than a separate `list` directive so that
one mechanism covers every reusable value: they are defined, spliced,
checked for cycles and reported the same way, and a rule that uses one is
reset on a reload when the list changes, like an address variable.

`rules.conf` defines `HOME_NET` (RFC 1918, loopback, and IPv6 ULA and
link-local) and `EXTERNAL_NET` (`!$HOME_NET`). Edit `HOME_NET` for your
network. `detect:ttl_anomaly` with `scope:external` reads `$HOME_NET`.

A rule's identity across reloads includes its expanded addresses, so
changing a variable resets the state (detection_filter windows, detector
tables) of every rule that uses it.

### arpbind

`arpbind IP MAC` pins an IPv4 address to a MAC address for
`detect:arp_spoof` (kind `static_violation`). Like `var`, it can come
anywhere in the file. Errors are reported as `file:line`: a malformed
line, an address that is not IPv4 or is `0.0.0.0`, a MAC that is not six
hex octets, a broadcast, multicast or all-zero MAC, and the same address
bound twice.

```
arpbind 192.168.1.1 aa:bb:cc:dd:ee:ff
```

Bind the gateway and other hosts whose MAC never changes. A bound address
is never learned from traffic, so `mac_change` and `flip_flop` never fire
for it: `static_violation` covers it, on the first packet that claims
another MAC.

## Options

Options are `key:value;` pairs inside the parentheses (the last `;` is
optional). Strings are in double quotes, where `\"`, `\\` and `\;` are the
escapes.

### msg, sid, rev, severity, category

| option | rule |
|---|---|
| `msg:"text";` | required, non-empty |
| `sid:N;` | required, 1 to 2^31-1, unique in the file. Local rules use 1000000 and up |
| `rev:N;` | default 1 |
| `severity:low\|medium\|high\|critical;` | default `medium`. `ids query -severity` filters on it |
| `category:NAME;` | letters, digits, `_` and `-` |

```
alert icmp any any -> any any (msg:"ICMP seen"; sid:1000907; rev:2; severity:low; category:recon;)
```

### flags (tcp only)

Letters `S A F R P U`. Without a suffix it is an exact match of those six
flags; `+` means "at least these"; `0` means none set.

```
alert tcp any any -> any any (msg:"Bare SYN"; flags:S; sid:1000908;)
alert tcp any any -> any any (msg:"Any segment with FIN"; flags:F+; sid:1000909;)
alert tcp any any -> any any (msg:"Null scan"; flags:0; sid:1000910;)
```

### content and nocase

`content:"text";` is a substring of the transport payload. `|0d 0a|` writes
hex bytes and `\|` a literal bar. It is repeatable, and all contents must
match. `nocase;` makes the content just before it case-insensitive (ASCII
only).

On a TCP flow the stream stage reassembles (see `app_proto` below), the
contents may instead all match the messages that the packet completed:
the whole HTTP head, DNS message, FTP line or TLS ClientHello, however
the sender split it. All contents must match in one of the two, the
payload or the messages. A content-only rule can therefore match both
the segment that carries a string and the one that completes its
message; dedup folds the second into the summary.

```
alert tcp any any -> any 80 (msg:"cmd.exe in HTTP"; content:"cmd.exe"; nocase; sid:1000911;)
alert tcp any any -> any 25 (msg:"SMTP line ending then DATA"; content:"|0d 0a|DATA"; sid:1000912;)
```

### same_ip, same_port

`same_ip;` matches when the source and destination addresses are equal;
`same_port;` when the source and destination ports are (tcp and udp
rules only). Neither takes a value. Together they catch the land attack,
a SYN whose source is its own destination.

```
alert tcp ![127.0.0.0/8,::1] any -> any any (msg:"Land attack"; same_ip; same_port; flags:S+; sid:1000003;)
```

Loopback traffic is excluded in `rules.conf`: a host legitimately talks
to itself over `lo` all the time.

### eth_dst

`eth_dst:broadcast;` matches frames sent to `ff:ff:ff:ff:ff:ff`.
`eth_dst:multicast;` matches any other group address (the least
significant bit of the first octet set: `01:00:5e:...`, `33:33:...`).
`eth_dst:zero;` matches `00:00:00:00:00:00`, the destination Linux puts on
frames captured on `lo`. A leading `!` negates: `eth_dst:!zero;` matches
every frame whose destination is not all zeros. Packets without an
Ethernet header (e.g. from a raw-IP capture) match none of the three, so
the negated forms match them.

`rules.conf` uses `eth_dst:!zero;` on the land rules: a WSL2 or
systemd-resolved DNS proxy answers from 127.0.0.x port 53 to itself over
`lo`, which is a land packet in form but not an attack.

### arp_op

`arp_op:request;` or `arp_op:reply;` matches the ARP operation. It is
valid on `arp` rules only, and cannot be combined with `detect`. With a
pass rule it silences ARP from given addresses, e.g. a proxy-ARP router
(see `detect:arp_spoof`).

```
alert arp any any -> any any (msg:"ARP reply"; arp_op:reply; sid:1000923;)
```

### itype, icode

`itype:N;` and `icode:N;` (0 to 255) match the ICMP or ICMPv6 type and
code. They are valid on `icmp` and `ip` rules and only match packets
that carry an ICMP header (not non-first fragments). ICMPv4 and ICMPv6
number their types differently: Echo Request is 8 in ICMPv4 and 128 in
ICMPv6; Time Exceeded is 11 and 3.

```
alert icmp any any -> 255.255.255.255 any (msg:"Smurf"; itype:8; sid:1000006;)
alert icmp any any -> any any (msg:"Traceroute"; itype:11; detection_filter:track by_dst, count 5, seconds 10; sid:1000408;)
```

### ttl

`ttl:N;`, `ttl:<N;` or `ttl:>N;` compares the IPv4 TTL or IPv6 hop
limit (N from 0 to 255; `<0` and `>255` are errors since they can never
match). ARP rules cannot use it.

```
alert ip $EXTERNAL_NET any -> any any (msg:"Low TTL from outside"; ttl:<3; sid:1000409;)
```

### dsize

`dsize:N;`, `dsize:<N;`, `dsize:>N;` or `dsize:N<>M;` (inclusive, N ≤ M)
compares the payload size in bytes, 0 to 65535. The payload is the data
after the transport header: for TCP and UDP the segment or datagram data,
for ICMP the data after the 4-byte header, and for Echo Request and Reply
the data after the identifier and sequence number, so `dsize` of a ping
is what `ping -s` asked for. A packet whose payload start is unknown (a
non-first fragment, a truncated header) never matches. Fragments are not
reassembled: a first fragment's `dsize` is the part of the payload it
carries, so a fragmented `ping -s 8000` on a 1500-byte MTU has a `dsize`
of 1472. ARP rules cannot use it.

```
alert icmp any any -> any any (msg:"Oversized ICMP Echo Request"; itype:8; dsize:>1472; sid:1000902;)
alert udp any any -> any 53 (msg:"Large DNS query"; dsize:512<>65535; sid:1000921;)
```

### app_proto, app_field, app_reason

These match what the application parser (Module 4) decoded.

On TCP ports 21 (FTP), 53 (DNS), 80, 8000 and 8080 (HTTP) and 443 and
8443 (TLS) (`-stream-ports` changes the set), the stream stage
reassembles each message first, so the parser sees whole HTTP heads, DNS
messages, FTP lines and TLS ClientHellos. The packet that completes a
message carries it; the packets before it carry no fields at all (they
are not malformed). A packet can complete several messages (HTTP
pipelining, several DNS messages or FTP lines in one segment): all
`app_field` and `app_reason` options of a rule must then be satisfied by
one of them. A flow the stream stage cannot follow (picked up mid-stream
and not yet at a message boundary, or after a gap) is parsed one segment
at a time, as on other ports.

- `app_proto:dns|http|ftp|tls;`: the parser recognized that protocol.
- `app_field:KEY=VALUE;`: field KEY equals VALUE, ignoring case. VALUE may
  be quoted. Repeatable.
- `app_reason:malformed|suspicious;`: the parser recorded a reason of that
  kind.

```
alert udp any any -> any 53 (msg:"TXT lookup"; app_proto:dns; app_field:qtype_name=TXT; sid:1000913;)
alert tcp any any -> any any (msg:"curl user agent"; app_proto:http; app_field:user_agent="curl/8.5.0"; sid:1000914;)
alert tcp any any -> any any (msg:"Broken HTTP"; app_proto:http; app_reason:malformed; sid:1000915;)
alert tcp any any -> any any (msg:"TLS without SNI"; app_proto:tls; app_field:sni_status=absent; sid:1000916;)
```

| protocol | fields |
|---|---|
| dns | `id`, `is_response`, `rcode`, `qdcount`, `ancount`, `nscount`, `arcount`, `dns_len`, `qname`, `qtype`, `qtype_name`, `qclass` (first question only) |
| http | requests: `method`, `uri`, `uri_decoded`, `query`, `version`, `request_complete`; responses: `status_code`; headers: `host`, `user_agent`, `content_type`, `content_length`, `auth_basic`, `headers_raw` |
| ftp | `command`, `argument` (the PASS argument is always `<redacted>`), `response_code` |
| tls | `sni`, `sni_status` (`found`, `absent`, `truncated`) |

HTTP fields in detail:

- `uri_decoded`: the URI percent-decoded once, then overlong UTF-8
  sequences replaced by the character they encode (`%c0%ae` is `.`,
  `%c0%af` is `/`). Overlong forms are invalid UTF-8 that old decoders
  (IIS 4/5, CVE-2000-0884) accepted, so `/%c0%ae%c0%ae/` walked out of the
  web root past filters looking for `../`. The 2-, 3- and 4-byte overlong
  forms are all decoded; each one also records the suspicious reason
  `overlong utf-8 encoding`.
- `query`: the part of the URI after the first `?` and before any `#`,
  with `+` turned into a space and then percent-decoded once. Absent
  without a `?`. SQL injection and command injection rules read this, so
  `select+shoes` is `select shoes`.
- `headers_raw`: every header line of the request or response, joined by
  `\n`, cut at 8 KiB. The values of `Authorization` and
  `Proxy-Authorization` are replaced by `<redacted>`, so credentials never
  reach a rule, an alert or the log. For Log4Shell and Shellshock, whose
  payloads can hide in any header.

Reasons the parsers can record include `double percent-encoding`
(suspicious, http: decoding the URI a second time reveals a `../`, `..\`
or NUL byte; double encoding alone is not flagged), `overlong utf-8
encoding` (suspicious, http), `long high-entropy label (possible DNS
tunnelling)` (suspicious, dns), and `qname: compression loop: pointer
does not point backwards`, `query has no questions` and `invalid request
line` (malformed). `app_reason` matches the kind only; the text is for
people, and `app_content:suspicious_reason,"..."` matches the text.
Credentials are never stored: the HTTP `Authorization` header only sets
`auth_basic=true`.

### app_content

`app_content:KEY,"text";` is a substring of the application field KEY
(any key from the table above, or `malformed_reason` /
`suspicious_reason`). The string takes the same `|hex|` and escapes as
`content`. `app_content:KEY,"text",nocase;` ignores ASCII case.
Repeatable; all must match, and like `app_field` they must all match the
same message of a packet. A missing field never matches.

```
alert tcp any any -> any any (msg:"sqlmap"; app_proto:http; app_content:user_agent,"sqlmap",nocase; sid:1000930;)
```

### app_domain

`app_domain:KEY,NAMES;` matches when field KEY is one of NAMES or a
subdomain of one, ignoring case and a trailing dot. NAMES is a domain
name, a `[a,b]` list, or a name-list variable. `dns.google` matches
`dns.google` and `x.dns.google`, but not `evildns.google`. Repeatable.

```
alert tcp any any -> any 443 (msg:"DoH"; app_proto:tls; app_domain:sni,$DOH_SERVERS; sid:1000111;)
```

### regex

`regex:KEY,"pattern";` searches application field KEY with a Go
regular expression (RE2 syntax). `regex:data,"pattern";` searches the
application data: the messages the packet completed, or its payload if it
completed none (the same two places `content` looks). `regex:data` is
valid on any IP rule; field regexes need `ip`, `tcp` or `udp`.
Repeatable; all must match.

- Case: write `(?i)` in the pattern. `nocase` is rejected, so it is never
  silently ignored.
- Quoting: the pattern is a quoted string, so write `\"` for a quote and
  `\;` for a semicolon; every other backslash is passed to the regex as
  is (`\d`, `\b`, `\.`).
- Errors (a bad pattern, an empty one, an unknown key form) are load
  errors with the file and line.
- Cost: RE2 guarantees time linear in the input, with no backtracking.
  Patterns such as `(a+)+$` that make a backtracking engine (PCRE, as in
  Snort and Suricata) take exponential time on a crafted input (ReDoS)
  run in linear time here. The price is no backreferences (`\1`) and no
  lookaround (`(?=...)`, `(?<!...)`). Each evaluation reads at most the
  first 16 KiB of the field or data, so its cost is bounded by a constant
  whatever a packet carries. A match that starts inside the first 16 KiB
  but ends after it is missed.

```
alert tcp any any -> any any (msg:"UNION SELECT"; app_proto:http; regex:query,"(?i)\bunion\s+select\b"; sid:1000931;)
alert tcp any any -> any any (msg:"Shellshock"; app_proto:http; regex:headers_raw,"\(\)\s*\{"; sid:1000932;)
```

Content, app_content and app_domain are checked before regexes, so a
cheap literal in the same rule keeps the regex off most packets.

### stream_anomaly

`stream_anomaly;` matches a packet on which the stream stage saw an
anomaly; `stream_anomaly:REASON;` only that one. Valid on `tcp` and `ip`
rules.

| reason | the packet |
|---|---|
| `overlap_conflict` | retransmits bytes the stream already holds (the message in progress or the last one delivered) with different content. TCP stacks never do this; an attacker does, so that the IDS and the server each keep a different copy (Ptacek and Newsham, 1998). The message in progress is dropped and the direction resyncs at the next message start. Overlaps with bytes no longer held (skipped bodies, older messages) are not seen. |
| `oversize_headers` | makes an HTTP head longer than 16 KiB without its blank line |
| `too_many_ooo_segments` | is a 17th out-of-order segment waiting behind one gap in the same direction |

After an anomaly the direction is parsed one segment at a time until a
segment starts a new message, so the packet that carried it is parsed on
its own.

```
alert tcp any any -> any any (msg:"TCP overlap with different data"; stream_anomaly:overlap_conflict; sid:1000501; severity:high; category:evasion;)
```

### detection_filter

`detection_filter:track by_src|by_dst, count N, seconds S;` makes the rule
fire only once N matches for the same tracked address fall within S
seconds. The window slides with every match.

```
alert tcp any 21 -> any any (msg:"FTP brute force"; app_proto:ftp; app_field:response_code=530; detection_filter:track by_dst, count 5, seconds 30; sid:1000917;)
```

The alert's `details` carry `track`, `tracked_addr`, `count` and `seconds`.

### detect:syn_flood

`detect:syn_flood;` replaces per-packet matching with the SYN flood
detector. It is valid on `tcp` alert rules only and takes:

| option | meaning |
|---|---|
| `track:by_src\|by_dst;` | required: count per client or per server |
| `count:N;` | required: incomplete handshakes needed |
| `seconds:S;` | required: within this span |
| `min_incomplete_ratio:F;` | 0 to 1, default 0.8: incomplete / all handshakes over that span |
| `max_distinct_ports:N;` | default 5: fire only if the incomplete handshakes over that span hit at most N destination ports. A flood hammers one service; incompletes spread over more ports are a scan, left to `port_scan` |

The rule's addresses and ports select which handshakes (client to server)
it counts. `flags`, `content`, `app_*` and `detection_filter` are not
allowed with it.

```
alert tcp any any -> 192.0.2.0/24 [80,443] (msg:"SYN flood on web servers"; detect:syn_flood; track:by_dst; count:200; seconds:10; min_incomplete_ratio:0.9; sid:1000918; severity:high; category:dos;)
```

The alert's `details` carry `detector`, `track`, `tracked_addr`,
`incomplete`, `completed`, `ratio`, `distinct_ports`, `top_dst_port` and
`window`.

`count` is at most 100000 and `seconds` at most 86400, here and in
`detection_filter`.

### detect:port_scan, detect:host_sweep, detect:ping_sweep

The scan detectors count probes per source. A probe is:

- a TCP handshake that does not complete: refused (RST), unanswered
  (timed out) or reset by the prober after the SYN-ACK (a half-open scan
  of an open port). It is counted when the handshake ends. A completed
  handshake is never a probe.
- a TCP packet with only FIN, no flags (NULL) or FIN+PSH+URG (Xmas).
- a UDP datagram that the target answered with an ICMP port unreachable
  (ICMPv4 3/3, ICMPv6 1/4) sent back to the datagram's source. Plain UDP
  never counts, and UDP probes that get no answer are not seen.
- for `ping_sweep` only: an ICMP or ICMPv6 Echo Request.

| detector | counts, per source | options |
|---|---|---|
| `port_scan` | distinct destination ports (TCP and UDP apart), over any hosts | `distinct_ports:N; seconds:S;` |
| `host_sweep` | distinct hosts probed on the same port and transport; one alert per swept port | `distinct_hosts:N; seconds:S;` |
| `ping_sweep` | distinct hosts sent an Echo Request | `distinct_hosts:N; seconds:S;` |

The rule fires when N distinct ports or hosts were each probed within the
last S seconds. N is at most 1000. The scan detectors always track the
source: `track` and `count` are not allowed. Each probe is checked like a
packet from the prober to the target: the whitelist and pass rules apply
to the prober, and the rule's addresses and ports select which probes it
counts. The rule's protocol selects the probe types: `ip` takes TCP and
UDP probes, `tcp` or `udp` only that kind; `ping_sweep` takes `ip` or
`icmp`.

```
alert ip any any -> 192.0.2.0/24 any (msg:"Port scan of the DMZ"; detect:port_scan; distinct_ports:20; seconds:10; sid:1000919; severity:medium; category:recon;)
alert udp any any -> any any (msg:"UDP host sweep"; detect:host_sweep; distinct_hosts:30; seconds:60; sid:1000920; severity:medium; category:recon;)
```

Details: all three carry `detector`, `track` (`by_src`), `tracked_addr`,
`seconds` and `window` (the span of the stored probes). `port_scan` adds
`distinct_ports`, `scan_types` (probes per kind among the counted ports,
e.g. `syn:18,udp:2`; kinds are `syn`, `fin`, `null`, `xmas`, `synfin`,
`udp`), `target_hosts`, `ports` and `open_ports` (ports that answered a
SYN with SYN-ACK). `host_sweep` adds `dst_port`, `proto`,
`distinct_hosts`, `scan_types` and `hosts`; `ping_sweep` adds
`distinct_hosts` and `hosts`. Lists hold at most 20 entries.

### detect:ttl_anomaly

Flags packets whose hop distance does not fit their source address, a
sign of a spoofed source. The initial TTL of a packet is taken to be the
smallest of 32, 64, 128 and 255 that is at least its TTL, and the
distance is the difference. Per source, up to 4 distances are kept with
a sample count each; a distance with `min_samples` samples is
established. Once a source has an established distance, a packet whose
distance is more than `max_hop_diff` from every established one is
anomalous. The rule fires when `count` anomalous packets from one source
fall within `seconds`.

| option | meaning |
|---|---|
| `count:N; seconds:S;` | required |
| `min_samples:N;` | default 10 |
| `max_hop_diff:N;` | 0 to 255, default 3 |
| `scope:external\|all;` | default `external`: track only sources outside `$HOME_NET`, which must then be defined |

TTLs of 5 or less are ignored (traceroute probes, `ttl:` rules cover
them). Machines with different initial TTLs behind one NAT address give
the same distance, so they do not trip it. An anomalous packet still
counts as a sample of its distance, so a lasting route change fires once
and is then established. Sources are held in an LRU table capped at the
engine's key limit and forgotten after an hour without packets. The
rule's protocol and addresses select which packets are counted.

Packets of TCP connections that completed their handshake never count as
anomalous, only as samples: load balancers, anycast and per-flow ECMP
send each connection from one server address over its own path, so the
distance is stable within a connection but differs between connections,
and a spoofer cannot complete a handshake for an address whose traffic it
does not receive. An anomalous SYN or SYN-ACK of a handshake still in
progress is held until the handshake ends; it is dropped if the handshake
completes and counted at the time it fails or times out otherwise. UDP,
ICMP and TCP of connections not seen opening are checked at once.

```
alert ip any any -> any any (msg:"TTL anomaly"; detect:ttl_anomaly; count:5; seconds:60; min_samples:10; max_hop_diff:3; sid:1000601;)
```

Details: `detector`, `track` (`by_src`), `tracked_addr`, `count`,
`seconds`, `window`, `established_distances` (`distance(samples)`),
`anomalous_distances`, `sample_ttls` and `max_hop_diff`.

### detect:frag_attack

Checks IPv4 and IPv6 fragments. It is valid on `ip` alert rules only;
`kind` selects the check:

| kind | fires on | options |
|---|---|---|
| `overlap` | a fragment that shares bytes with an earlier fragment of the same datagram (teardrop, IDS evasion). An exact duplicate of an earlier fragment is not an overlap | |
| `tiny` | a first fragment too short for the TCP (20 bytes) or UDP (8 bytes) header, an IPv6 first fragment without the whole header chain (RFC 7112), or a non-final fragment carrying fewer than `min_size` bytes | `min_size:N;` default 256 |
| `oversize` | a fragment that ends past byte 65535 (ping of death) | |
| `flood` | `count` datagrams from one source left incomplete when the fragment timeout (30 s) expires, within `seconds` | `count:N; seconds:S;` required |

Datagrams are tracked by (source, destination, protocol, IP ID) for IPv4
and (source, destination, ID) for IPv6, up to 64 fragments each; a
datagram with more stops being checked and is counted in the
`FragmentsOverLimit` statistic. IPv4 fragments with a bad header checksum
are ignored (the receiver drops them). Alerts are deduplicated per
source.

```
alert ip any any -> any any (msg:"Overlapping IP fragments"; detect:frag_attack; kind:overlap; sid:1000701;)
alert ip any any -> any any (msg:"IP fragment flood"; detect:frag_attack; kind:flood; count:50; seconds:30; sid:1000704;)
```

Details: `detector`, `kind`, and for per-fragment kinds `ip_id`,
`frag_offset`, `payload_len` and `more_frags`, plus `fragment`,
`overlaps` and `fragments_seen` (overlap), `reason` and `min_size`
(tiny), `end` and `limit` (oversize). `flood` carries `track`,
`tracked_addr`, `incomplete_datagrams`, `seconds`, `window` and
`timeout`.

### detect:arp_spoof

Checks ARP for spoofing (cache poisoning). It is valid on `arp` alert
rules only; `kind` selects the check. The rule's addresses match the ARP
sender address (source) and target address (destination).

The engine keeps an IP→MAC binding table shared by all `arp_spoof`
rules, learned only from the sender address and MAC of ARP requests and
replies (never from IP traffic, whose Ethernet source is a router for
off-link addresses). Per address it holds the current MAC, when it was
first and last seen, and the last 8 changes. It is capped at the engine's
key limit with LRU eviction, and an address unheard for 4 hours is
forgotten. The table is fed by every ARP packet, including whitelisted
and passed ones; the whitelist and pass rules only silence alerts.

| kind | fires on | options |
|---|---|---|
| `static_violation` | a packet claiming an `arpbind` address with another MAC | |
| `mac_change` | a learned address moving to a new MAC (includes old MAC and how long it held) | |
| `flip_flop` | `count` returns of one address, within `seconds`, to a MAC in its recent history | `count:N; seconds:S;` required |
| `unsolicited_reply` | `count` replies for one (address, MAC), within `seconds`, that answer no request | `count:N; seconds:S;` required |
| `multi_ip` | one MAC sending replies for `count` distinct addresses within `seconds` (at most 1000) | `count:N; seconds:S;` required |
| `mismatch` | an Ethernet source MAC different from the ARP sender MAC | |
| `invalid_mac` | a broadcast, multicast or all-zero ARP sender MAC | |

- A sender address of `0.0.0.0` (an RFC 5227 probe) teaches nothing and
  is checked by `invalid_mac` only.
- A reply is solicited when the address it answers for (sender address)
  was requested by the address it is sent to (target address) within the
  last 5 s. A reply does not use the request up, so a host that answers
  twice is not flagged; a reply to `0.0.0.0` answers a probe.
- A gratuitous ARP (sender address equals target address, request or
  reply) announces a host's own address. The first two per (address, MAC)
  within `seconds` are free, which covers a boot or failover
  announcement; later ones count as unsolicited replies.
- `multi_ip` fires legitimately for a proxy-ARP router, which answers
  for a whole remote subnet with its own MAC. Silence it with a pass rule
  for its replies:
  `pass arp 10.20.0.0/24 any -> any any (msg:"proxy ARP"; arp_op:reply; sid:1000899;)`.
- On a switched network the IDS only sees broadcast ARP and ARP to or
  from its own host, unless it is on a mirror port.

```
arpbind 192.168.1.1 aa:bb:cc:dd:ee:ff
alert arp any any -> any any (msg:"ARP static binding violated"; detect:arp_spoof; kind:static_violation; sid:1000801; severity:critical; category:spoofing;)
alert arp any any -> any any (msg:"ARP cache poisoning"; detect:arp_spoof; kind:flip_flop; count:3; seconds:60; sid:1000803; severity:high; category:spoofing;)
```

Details: `detector`, `kind`, `ip` (sender address), `op` (`request` or
`reply`), plus `claimed_mac` and `bound_mac` (static_violation);
`old_mac`, `new_mac` and `old_stable` (mac_change); `mac`,
`previous_mac`, `returns`, `changes`, `seconds` and `window`
(flip_flop); `mac`, `replies`, `gratuitous`, `seconds` and `window`
(unsolicited_reply); `mac`, `distinct_ips`, `ips` and `seconds`
(multi_ip); `eth_src` and `arp_sender_mac` (mismatch); `mac` and
`reason` (invalid_mac).

### detect:udp_flood

Counts UDP traffic per tracked address over a sliding window and fires
when it reaches `count` packets (or bytes) within `seconds` while little
comes back. Valid on `udp` alert rules only.

| option | meaning |
|---|---|
| `track:by_src\|by_dst;` | required: count per sender or per receiver |
| `count:N; seconds:S;` | required. `count` is at most 100000, except with `metric:bytes`, where it may be up to 2^40 |
| `metric:packets\|bytes;` | default `packets`. Bytes are the UDP Length field (header plus data), so they are right in captures cut short by a snaplen |
| `max_reply_ratio:F;` | 0 to 1, default 0.02: fire only if replies / forward packets over the window is at most F |

A reply is a UDP packet going back:

- `by_src`: the reverse of a flow (addresses and ports swapped) that the
  sender used in the window. A sender whose flows are answered is
  talking, not flooding.
- `by_dst`: any UDP packet from the receiver to one of the addresses that
  sent it counted traffic in the window, on any ports; under a spoofed
  flood the question is whether the victim answers the senders at all.
  Traffic a host sends to itself (127.0.0.1 to 127.0.0.1 on `lo`) uses
  the `by_src` test instead, since every packet would otherwise be its
  own reply.

ICMP errors (port unreachable) are never replies: a flood at a closed
port gets only those back and still fires. Replies are looked for among
all UDP packets, whitelisted and passed ones included; forward traffic is
what the rule's addresses and ports select, after the whitelist and pass
rules. The ratio is what keeps busy but two-way UDP quiet: QUIC
acknowledges about one packet in 10 to 20, and a call sends media both
ways.

The window is a ring of 10 sub-buckets (`seconds`/10 each), so the sum
covers between 90% and 100% of `seconds` and a threshold may be reached
up to a tenth of the window late. Memory per tracked address is fixed
whatever `count` is.

```
alert udp any any -> any any (msg:"UDP flood against one destination"; detect:udp_flood; track:by_dst; count:10000; seconds:5; sid:1000010;)
alert udp any any -> any any (msg:"UDP flood (bytes)"; detect:udp_flood; track:by_dst; metric:bytes; count:100000000; seconds:5; sid:1000012;)
```

Details: `detector`, `track`, `tracked_addr`, `metric`, `packets`,
`bytes`, `replies`, `reply_ratio`, `max_reply_ratio`, `packets_per_sec`,
`bytes_per_sec`, `top_dst_port`, `seconds`, and for `by_dst`
`distinct_sources` (reported as `100+` above 100).

Reflection and amplification attacks arrive from the reflectors' service
ports; a plain rule with `detection_filter` covers them (see
`$REFLECTOR_PORTS` in `rules.conf`).

### detect:icmp_flood

Counts ICMP packets of one kind per address over the same kind of
sliding window as `udp_flood` and fires at `count` within `seconds`.
Valid on `icmp` alert rules only.

| kind | counts | tracked address |
|---|---|---|
| `echo` | Echo Requests (ICMP 8, ICMPv6 128). Replies do not lower it: a flood the victim answers costs it twice | `track:by_src\|by_dst;`, required |
| `unsolicited_reply` | Echo Replies (0, 129) that answer no request seen in the last 10 s from the receiver to the sender (or to a broadcast or multicast address) with the same identifier and sequence number: the victim end of a smurf or reflection attack | the receiver |
| `error_flood` | ICMP errors: destination unreachable, time exceeded, parameter problem (3, 11, 12; ICMPv6 1, 3, 4) and ICMPv6 packet too big (2) | the receiver |

`count:N; seconds:S;` are required; `track` is only allowed with
`kind:echo`. Echo Requests are recorded for `unsolicited_reply` whether
or not they are whitelisted or passed; a request is not used up by its
reply, so duplicates and every member of a group may answer it. Replies
too short to carry an identifier and sequence number are ignored.

A port scan or UDP flood against closed ports makes the target send port
unreachables to the scanner. Hosts rate-limit these (Linux sends at most
1000 a second in total and far fewer to one destination), so
`error_flood` at 1000 in 5 s stays quiet for them, but not on loopback,
which is not rate-limited.

```
alert icmp any any -> any any (msg:"ICMP Echo flood"; detect:icmp_flood; kind:echo; track:by_dst; count:1000; seconds:5; sid:1000020;)
alert icmp any any -> any any (msg:"Smurf victim"; detect:icmp_flood; kind:unsolicited_reply; count:100; seconds:5; sid:1000022;)
```

Details: `detector`, `kind`, `track`, `tracked_addr`, `packets`,
`packets_per_sec`, `seconds`, `distinct_sources` (`distinct_destinations`
for `echo` `by_src`; `100+` above 100), and for `error_flood`
`top_error` (e.g. `Destination Unreachable (port unreachable)`).

### detect:icmp_tunnel

Looks for data carried in Echo payloads (ptunnel, icmpsh, hans). Per
(client, server) pair, where the client sends the Echo Requests and the
server the Replies, it keeps the size and Shannon entropy of the last
`count` payloads, in either direction, that are not a standard ping
pattern. It fires when `count` of them fall within `seconds` and they
come in at least 3 distinct sizes or average more than 6 bits of entropy
per byte. Valid on `icmp` alert rules; `count:N; seconds:S;` are
required.

Standard patterns, which never count:

- Linux and BSD: byte i is `i` (counting 0x00, 0x01, ... and wrapping),
  optionally after an 8- or 16-byte timestamp whose bytes are not
  checked; at least one counting byte must follow the timestamp.
- Windows: `abcdefghijklmnopqrstuvw` repeated.
- All zero bytes, and no data at all.

`ping -p` fills the payload with a repeated pattern of one size and low
entropy, so it does not fire. Only payloads over 64 bytes can reach 6
bits of entropy. A tunnel can hide up to 16 bytes per packet in the
"timestamp" of an otherwise standard payload.

```
alert icmp any any -> any any (msg:"ICMP tunnel"; detect:icmp_tunnel; count:10; seconds:60; sid:1000901;)
```

Details: `detector`, `client`, `server`, `payloads`, `distinct_sizes`,
`avg_entropy`, `payload_hex` (the first 16 bytes of the payload that
fired), `payload_len`, `seconds`, `window`, `min_sizes` and
`min_entropy_bits`. Alerts are deduplicated per (sid, client, server).

### detect:slowloris

Slow HTTP denial of service: many connections each held open by a
request that never finishes. It needs the stream stage, which tracks
the HTTP state of each connection on the HTTP ports (80, 8000 and 8080
by default). Valid on `tcp` alert rules. `kind`, `track:by_src|by_dst`
and `count:N` are required. A connection qualifies while:

| kind | the connection | options (default) |
|---|---|---|
| `slow_headers` | has a request head in progress for more than `min_age`, and the client sent data within the last `seconds` | `min_age:10; seconds:30;` |
| `slow_body` | has a request body in progress for more than `min_age` (counted from the start of the head), with more than `min_remaining` bytes of its Content-Length still to come, data within `seconds`, and fewer than `min_rate` bytes per second received on average | `min_age:20; seconds:30; min_rate:100; min_remaining:10240;` |
| `slow_read` | has had a zero TCP window from the client for more than `min_age` | `min_age:20;` |

`min_age` and `seconds` are in seconds. `seconds` does not apply to
`slow_read`, and `min_rate` and `min_remaining` apply only to
`slow_body`. The rule fires when `count` qualifying connections share
the tracked address (the client for `by_src`, the server for `by_dst`),
then once for every further connection that qualifies. A connection
stops counting when it closes (FIN, RST, or 2 minutes without packets),
when its request completes, when its window opens, or when it stops
qualifying.

A browser's idle keep-alive connections have no request in progress and
never count, however many there are. Connections whose chunked or
unknown-length body is in progress do not count for `slow_body`. The
table holds at most 50000 connections, dropping the least recently
active; conditions are re-checked on every packet and when the engine
is flushed, so a connection can qualify while it sends nothing.

```
alert tcp any any -> any any (msg:"Slowloris"; detect:slowloris; kind:slow_headers; track:by_src; count:20; sid:1000030;)
alert tcp any any -> any any (msg:"R-U-Dead-Yet"; detect:slowloris; kind:slow_body; track:by_src; count:10; sid:1000032;)
```

Details: `detector`, `kind`, `track`, `tracked_addr`, `flows`, `count`,
`oldest_age`, `min_age`, `targets` (up to 5 server `ip:port`),
`distinct_targets`, `clients`, `sample_flow_ids` (up to 5), and
`seconds`, `min_rate` and `min_remaining` where they apply.

### DNS detectors

Four detectors read DNS messages, over UDP and over TCP (every message of
a reassembled segment). They are valid on `ip`, `tcp` and `udp` alert
rules. The rule's addresses and ports are matched against the packet: a
query goes client to server, a response server to client. The whitelist
and pass rules apply to the packet's source.

**The outstanding query table.** For `dns_spoof` and
`dns_amplification` the engine records every query (whitelisted and
passed ones included) under its transaction: client address and port,
server address, and DNS id, with the question (name, lowercased, and
type) and the query size. A response is looked up by the reversed
transaction and is then one of:

- *matched*: a question of its transaction has the same name and type.
  That question is removed, so a second copy of the answer is
  unsolicited. A response without a question matches the oldest one.
- *mismatch*: its transaction has questions waiting, none of them its
  own.
- *unsolicited*: nothing is waiting for its transaction.

A question is forgotten 10 s after it was last sent (stub resolvers give
up after about 5 s); a retransmission refreshes it. At most 8 questions
wait per transaction and the table holds at most the engine's key limit
of transactions, dropping the least recently queried (counted in the
`dns_queries` table statistics).

#### detect:dns_spoof

| kind | fires on | options |
|---|---|---|
| `unsolicited_response` | `count` unsolicited responses to one client within `seconds`. One now and then is normal (a late answer after a retry, a server answering a retransmission twice) | `count:N; seconds:S;` required |
| `id_race` | `count` distinct ids among unsolicited responses for one (client, server, name) within `seconds`, while the client has a question for that name waiting at that server (on any port and id): forged answers racing the real one, each guessing an id (the Kaminsky attack). Only unsolicited responses count, so a client asking one name over and over and getting answers never fires; and a reflection victim, flooded with answers to queries it never sent, has no question waiting, so it gets `unsolicited_response` and `dns_amplification` but not this | `count:N; seconds:S;` required, `count` at most 1000 |
| `qname_mismatch` | one response whose client, ports and id match a waiting query but whose question does not: an answer forged for the wrong query, or a broken server | none |

The capture must see the queries: on a sensor that sees only responses
(asymmetric routing) every response is unsolicited. A reflection
attack also fires `unsolicited_response` next to `dns_amplification`:
the victim receives many answers it did not ask for, which is what that
kind counts. Resolvers randomize
letter case (DNS 0x20); names are compared lowercased.

Details: `detector`, `kind`, `client`, `server`, `qname`, `id`, and
`responses`, `seconds` and `window` (unsolicited_response),
`distinct_ids` and `seconds` (id_race), `client_port` (qname_mismatch).
Alerts are deduplicated per (sid, client).

#### detect:dns_amplification

Per victim (the address responses go to) it sums over `seconds` the
response bytes, the bytes of the queries they matched, and the bytes of
unsolicited or mismatched responses. Reflection spoofs the victim's
address in small queries (ANY, DNSSEC, big TXT) sent to open resolvers,
so the victim receives large answers to queries it never sent. It fires
when:

- `unmatched`: unmatched response bytes reach `min_bytes`, or
- `ratio`: response bytes reach `min_bytes` and are at least `min_ratio`
  times the matched query bytes.

| option | meaning |
|---|---|
| `min_bytes:N;` | required, up to 2^40 |
| `seconds:S;` | required |
| `min_ratio:F;` | 1 to 1000000, default 10. An ordinary answer is 2 to 5 times its query; ANY and DNSSEC answers used for reflection are 30 to 100 times |

Sizes are the DNS message length (`dns_len`). The window works like
`udp_flood`'s: 10 sub-buckets, fixed memory per victim. `rules.conf` also
has a plain rule for repeated ANY queries from one source. RFC 8482
(2019) lets servers answer ANY with a single small record, and most large
resolvers do, so one ANY query means little and the rule waits for 20
within 10 s.

Details: `detector`, `track` (`by_dst`), `tracked_addr`, `reason`,
`response_bytes`, `query_bytes`, `unmatched_bytes`, `ratio` (with matched
queries), `min_bytes`, `min_ratio`, `top_qtype` and `seconds`.

#### detect:dns_tunnel

Looks at queries per (client, registered domain). The registered domain
is the name's effective TLD plus one label by the Public Suffix List
(`golang.org/x/net/publicsuffix`), not its last two labels: those would
be `co.uk` for `www.bbc.co.uk`, lumping every British company into one
domain, and `github.io` for `alice.github.io`, one domain for every
GitHub Pages site. Counting subdomains per `co.uk` would make a busy
browser look like a tunnel. Names that are a public suffix themselves
are skipped. The subdomain is everything left of the registered domain.

| kind | fires on | options |
|---|---|---|
| `subdomains` | `count` distinct subdomains within `seconds` whose average Shannon entropy is at least `min_entropy` bits per character or whose average length is at least `min_length` (dots removed) | `count:N; seconds:S;` required (`count` at most 1000); `min_entropy:F;` 0 to 8, default 3.5; `min_length:N;` default 50 |
| `txt` | `count` TXT or NULL queries within `seconds`: the record types tunnels use to bring data back | `count:N; seconds:S;` required |

`allow:NAMES;` (either kind) skips registered domains that are one of
NAMES or under one. Data encoded into names (iodine, dnscat2, DNS
exfiltration) makes every query a new, long, random-looking subdomain;
hostnames people pick are short and repeat letters. Entropy is measured
per character of the subdomain, so a short label cannot reach a high
value (a 16-character label has at most 4 bits).

`rules.conf` passes `$DNS_TUNNEL_ALLOW`, the reverse-lookup zones
`in-addr.arpa` and `ip6.arpa`: a host resolving many peers' addresses
asks for many distinct numeric names under one zone.

Details: `detector`, `kind`, `client`, `registered_domain`, `seconds`,
and for `subdomains` `unique_subdomains`, `avg_entropy`, `avg_length`,
`txt_null_cname_mx` (share of those query types), `sample_qnames` (the
last 3), `min_entropy` and `min_length`; for `txt` `txt_null_queries` and
`sample_qnames`. Alerts are deduplicated per (sid, client, server).

#### detect:dns_nxdomain_burst

Per client, the distinct names answered NXDOMAIN (rcode 3) within
`seconds`. It fires when `count` are distinct and at least half have a
leftmost label with `min_entropy` bits per character (default 3.0):
malware with a domain generation algorithm (DGA) tries many random names
until one resolves. Typos (`gooogle.com`) and a broken search domain
(`printer.corp.example.com`) also fail in bursts, but on word-like names.
`count:N; seconds:S;` are required, `count` at most 1000.

Details: `detector`, `track` (`by_dst`), `tracked_addr`,
`nxdomain_names`, `high_entropy_names`, `min_entropy`, `seconds` and
`sample_qname`.

### DoH and DoT

DNS over HTTPS and over TLS bypass the local resolver, and with it any
DNS monitoring and filtering, including the detectors above. `rules.conf`
reports them as policy (severity low):

- DoH: a TLS ClientHello whose SNI is in `$DOH_SERVERS`, the public DoH
  endpoints documented by Google (`dns.google`), Cloudflare
  (`cloudflare-dns.com`, `one.one.one.one`), Quad9 (`dns.quad9.net`),
  OpenDNS/Cisco (`doh.opendns.com`, `doh.familyshield.opendns.com`,
  `doh.umbrella.com`), AdGuard and NextDNS. Subdomains match, so
  `cloudflare-dns.com` also covers `security.cloudflare-dns.com` and
  `mozilla.cloudflare-dns.com`. A DoH server on a name not in the list, or
  a client using Encrypted Client Hello, is not seen.
- DoT: any TCP SYN to port 853.

Detector rules cannot use `flags`, `content`, `app_*`, `stream_anomaly`,
`detection_filter`, `same_ip`, `same_port`, `eth_dst`, `itype`, `icode`,
`ttl`, `arp_op` or `dsize`.

## What happens after a match

1. The whitelist (`-whitelist CIDR,...`) and pass rules are checked first.
   Either one silences the packet.
2. `detection_filter` or the detector decides whether the rule fires.
3. Dedup: the first firing per (sid, address) is logged as an `alert`
   (per (sid, address, port) for `host_sweep`, per (sid, address, MAC)
   for `arp_spoof` `unsolicited_reply`, per (sid, MAC) for
   `multi_ip`, per (sid, client, server) for `icmp_tunnel` and
   `dns_tunnel`, and per (sid, client) for `dns_spoof`) with
   count 1. The address is the tracked one for `detection_filter` and
   `detect` rules, otherwise the packet's source. Later firings within 60 s
   of the first are folded into one `summary`, logged when the window
   closes, whose count is the total.

The engine clock is packet time, never the wall clock, so replaying a pcap
gives the same alerts every time.
