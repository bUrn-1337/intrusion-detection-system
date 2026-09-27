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

```
alert tcp any any -> any 80 (msg:"cmd.exe in HTTP"; content:"cmd.exe"; nocase; sid:1000911;)
alert tcp any any -> any 25 (msg:"SMTP line ending then DATA"; content:"|0d 0a|DATA"; sid:1000912;)
```

### app_proto, app_field, app_reason

These match what the application parser (Module 4) decoded.

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
| http | requests: `method`, `uri`, `uri_decoded`, `version`, `request_complete`; responses: `status_code`; headers: `host`, `user_agent`, `content_type`, `content_length`, `auth_basic` |
| ftp | `command`, `argument` (the PASS argument is always `<redacted>`), `response_code` |
| tls | `sni`, `sni_status` (`found`, `absent`, `truncated`) |

Reasons the parsers can record include `double percent-encoding`
(suspicious, http: decoding the URI a second time reveals a `../`, `..\`
or NUL byte; double encoding alone is not flagged), `long high-entropy label (possible DNS tunnelling)`
(suspicious, dns), and `qname: compression loop: pointer does not point
backwards`, `query has no questions` and `invalid request line`
(malformed). `app_reason` matches the kind only; the text is for people. Credentials are never stored: the HTTP
`Authorization` header only sets `auth_basic=true`.

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

The rule's addresses and ports select which handshakes (client to server)
it counts. `flags`, `content`, `app_*` and `detection_filter` are not
allowed with it.

```
alert tcp any any -> 192.0.2.0/24 [80,443] (msg:"SYN flood on web servers"; detect:syn_flood; track:by_dst; count:200; seconds:10; min_incomplete_ratio:0.9; sid:1000918; severity:high; category:dos;)
```

`count` is at most 100000 and `seconds` at most 86400, here and in
`detection_filter`.

## What happens after a match

1. The whitelist (`-whitelist CIDR,...`) and pass rules are checked first.
   Either one silences the packet.
2. `detection_filter` or the detector decides whether the rule fires.
3. Dedup: the first firing per (sid, address) is logged as an `alert`
   with count 1. The address is the tracked one for `detection_filter` and
   `detect` rules, otherwise the packet's source. Later firings within 60 s
   of the first are folded into one `summary`, logged when the window
   closes, whose count is the total.

The engine clock is packet time, never the wall clock, so replaying a pcap
gives the same alerts every time.
