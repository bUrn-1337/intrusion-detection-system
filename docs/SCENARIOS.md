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
(`w.Conn(...).Handshake()`, `Send`, `Close`, `SYN`, `Refuse`).

## expected.json

| field | meaning |
|---|---|
| `description` | what the traffic is and why these alerts are right |
| `alerts` | each entry must match **exactly one** alert record |
| `absent_sids` | sids that must not appear at all |
| `allow_extra` | if `false` (the default), any alert not matched by an entry fails |
| `args` | extra `ids run` flags, e.g. `["-whitelist", "10.0.0.0/8"]` |
| `rules` | rules file relative to the scenario directory |
| `log_must_not_contain` | strings (credentials) that must never appear in the log or on stdout |

An alert entry matches on stable fields only: `sid` and `kind` (`alert`
or `summary`) are required; `src_ip`, `dst_ip`, `src_port`, `dst_port`,
`count` (an inclusive `[min, max]`) and `details` (a subset of the alert's
details) are optional. Timestamps are never compared. Entries are matched
in order, so list the more specific ones first.

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
for attackers, `10.0.0.0/8` for clients and `198.18.0.0/15` for spoofed
sources.
