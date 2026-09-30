# Rules for Claude Code

Team-wide rules. Machine-specific notes (paths, OS quirks) go in
`CLAUDE.local.md`, which is gitignored; read it too if it exists.

## Git and the system
- NEVER run git commands that change repo state: no commit, push, branch, checkout,
  merge, rebase, reset, stash, or tag. Read-only git (status, diff, log) is fine.
- Leave all changes uncommitted in the working tree. The user commits manually.
- Never use sudo. When something needs privileges (e.g. `make setcap`), stop and
  ask the user to run the exact command.
- Kill background processes (test servers, captures) by PID, never `pkill -f`.

## Live testing workflow
- After finishing a step, always verify it live yourself; don't ask the user to test.
- Live capture needs capabilities: build with `make build` (bin/ids and
  bin/capturedump), then STOP and ask the user to run exactly `make setcap`.
  Wait for them to confirm, then run all live checks yourself. Never rebuild
  bin/ after setcap (it strips the capability); if you must rebuild, ask for
  setcap again. Benchmarks and pcap runs can use a scratch build instead
  (`go build -o $SCRATCH/ids ./cmd/ids`).
- Stop live captures with SIGINT (e.g. `timeout --preserve-status -s INT 15 ...`)
  so final stats print.
- Clean up afterwards: test servers, scripts, temporary rules and feed files.

## Tests and conventions
- Before reporting a step done: gofmt, `go build ./...`, `go vet ./...`,
  staticcheck, `go test -race ./...`, `make scenarios`.
- There is no `ids check` command: validate rules.conf with
  `go test ./internal/rules -run TestLoad`.
- New detectors follow docs/ADDING_A_DETECTOR.md; every detector needs a
  scenario that fires and a look-alike that must not (docs/SCENARIOS.md).
  Scenario pcaps are generated with internal/testutil/pcapgen, using
  generated timestamps (never real time) and documentation addresses.
- Mutation checks: break the logic on purpose (flip a comparison, drop a
  condition), confirm a test or scenario fails, then restore the file
  exactly (verify with a checksum or `git diff`).
- Fuzz new parsers and rule options (`make fuzz FUZZ=... FUZZTIME=...`, or
  `go test -fuzz` in the package).
- Don't change detection logic (thresholds, what fires) without telling the user.
- Credentials (HTTP Authorization, FTP PASS) must never appear in output or logs.

## Reports
- Don't mention MCP server status in reports.
