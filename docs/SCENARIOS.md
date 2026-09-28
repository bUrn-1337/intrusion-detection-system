# Scenarios

A scenario is a small capture plus the alerts it must (and must not)
produce. `make scenarios` runs every scenario through the real `ids run -r
FILE -no-tui` code path and fails with a readable diff. Every detector
needs at least one scenario that fires and one look-alike that must not.

## Layout

```
testdata/scenarios/<name>/
    expected.json    required
    capture.pcap     optional: a real capture, under 1 MB
    rules.conf       optional: default is the repo's rules.conf
```

Without `capture.pcap`, the pcap is generated at test time by the function
registered under `<name>` in `scenarioGenerators`
([cmd/ids/scenarios_test.go](../cmd/ids/scenarios_test.go)). Generators
live in [cmd/ids/scenario_gen_test.go](../cmd/ids/scenario_gen_test.go)
and use [internal/testutil/pcapgen](../internal/testutil/pcapgen), which
writes whole TCP conversations with correct sequence numbers
(`w.Conn(...).Handshake()`, `Send`, `Close`, `SYN`, `SYNACK`, `Refuse`)
and single frames with `w.Add(pcapgen.Pkt{...})`: any TCP flags, UDP,
ICMP Echo Requests, and ICMP port unreachables that quote another packet
(`Pkt{Proto: "icmp", Src: server, Dst: prober, Unreach: &probe}`, ICMPv6
for IPv6 addresses). `w.Step` sets the time between frames and `w.Wait`
skips time, for example to let unanswered handshakes time out.
`Pkt` also sets any ICMP type and code (`ICMP: &[2]uint8{11, 0}`), the
TTL or hop limit (`TTL`) and the Ethernet destination
(`EthDst: pcapgen.Broadcast`). For fragments, `pcapgen.Fragment(tb, pkt,
id, mtu)` splits a packet the way a sender with that MTU would, and
`w.AddFrag(pcapgen.Frag{...})` writes any hand-made fragment (overlaps,
tiny or oversized ones) with the offset in bytes.
`w.AddARP(pcapgen.ARP{Op: pcapgen.ARPReply, SenderIP: ..., SenderMAC:
..., TargetIP: ..., TargetMAC: ...})` writes an ARP frame; `EthSrc` and
`EthDst` override the Ethernet addresses (for a mismatch), and
`pcapgen.MAC(n)` gives host n the address `02:00:00:00:hi:lo`. `Pkt.EthSrc`
sets the Ethernet source of IP packets (`pcapgen.ZeroMAC` for loopback).
Echo Requests and Replies (`ICMP: &[2]uint8{0, 0}`) carry the identifier
and sequence number in `Echo: &[2]uint16{id, seq}` (default 1, 1) and
their data in `Payload`. Setting `w.Snap` cuts every later frame to that
many captured bytes while keeping its original length, like a capture
with a small snaplen; `udp_flood_bytes` uses it to write 100 MB of
datagrams in a small pcap.

For TCP stream reassembly, a `Conn` also writes segments out of the
ordinary: `SetISN(client, server)` picks the initial sequence numbers
(near 2^32 to test the wrap), `Seg(fromClient, off, data)` writes a
segment `off` bytes after the next sequence number (negative or
repeated for a retransmission, ahead for out-of-order) without moving
it, and `Advance(fromClient, n)` then moves it and writes the ACK.
`Push` sends without the peer's ACK, `Ack(fromClient, zeroWindow)`
writes a bare ACK (`Pkt.ZeroWindow` advertises a zero window), and
`Reset` a RST. A `Conn` used without `Handshake` is a connection the IDS
picked up mid-stream.

## expected.json

| field | meaning |
|---|---|
| `description` | what the traffic is and why these alerts are right |
| `alerts` | each entry must match **exactly one** alert record |
| `absent_sids` | sids that must not appear at all |
| `allow_extra` | if `false` (the default), any alert not matched by an entry fails |
| `args` | extra `ids run` flags, e.g. `["-whitelist", "10.0.0.0/8"]` |
| `rules` | rules file relative to the scenario directory |
| `extra_rules` | lines appended to the rules file (default or `rules`) for this scenario only, e.g. `["arpbind 10.1.1.1 02:00:00:00:00:01"]` or a pass rule |
| `log_must_not_contain` | strings (credentials) that must never appear in the log or on stdout |
| `stream_stats` | bounds on counters of the shutdown stats record's `stream` object, e.g. `{"overlap_conflicts": [1, 1], "evictions": [2000, 3999]}` |

An alert entry matches on stable fields only: `sid` and `kind` (`alert`
or `summary`) are required; `src_ip`, `dst_ip`, `src_port`, `dst_port`,
`count` (an inclusive `[min, max]`) and `details` (a subset of the alert's
details) are optional. Timestamps are never compared. Entries are matched
in order, so list the more specific ones first.

A rule that keeps matching logs one `alert`, then one `summary` whose
`count` is the total number of matches including the first. For a
detector, every probe or event after the threshold is a match: a scan of
1000 ports with `distinct_ports:20` logs an alert and a summary with
count 981.

## Example: adding `ftp_plaintext_pass`

1. Write the generator in `cmd/ids/scenario_gen_test.go`:

   ```go
   func genFTPPlaintextPass(w *pcapgen.Writer) {
       c := w.Conn("10.0.0.8", 45000, "192.0.2.21", 21)
       c.Handshake()
       c.Send(false, []byte("220 FTP server ready\r\n"))
       ftpLogin(c, "alice", "s3cretPw!", "230 User alice logged in.")
       c.Send(true, []byte("QUIT\r\n"))
       c.Send(false, []byte("221 Goodbye.\r\n"))
       c.Close()
   }
   ```

2. Register it: `"ftp_plaintext_pass": genFTPPlaintextPass,` in
   `scenarioGenerators`.

3. Create `testdata/scenarios/ftp_plaintext_pass/expected.json`:

   ```json
   {
     "description": "One successful FTP login. The cleartext password alerts once; with no 530s the brute-force rule stays quiet.",
     "alerts": [
       {"sid": 1000301, "kind": "alert", "src_ip": "10.0.0.8", "dst_ip": "192.0.2.21", "dst_port": 21, "count": [1, 1]}
     ],
     "absent_sids": [1000302],
     "log_must_not_contain": ["s3cretPw!"]
   }
   ```

4. Run `make scenarios`. If it fails, the message lists `missing:`,
   `unexpected:` and `forbidden:` alerts, followed by every alert that was
   logged. Copy fields from those lines only after checking that each alert
   is right.

5. Check that the scenario can fail: break the detector on purpose (for
   example, flip its threshold comparison), run `make scenarios`, confirm
   that your scenario fails, then revert.

Use documentation addresses: `192.0.2.0/24` for servers, `203.0.113.0/24`
for attackers, `10.0.0.0/8` for clients, `198.18.0.0/15` for spoofed
sources and `2001:db8::/32` for IPv6.
