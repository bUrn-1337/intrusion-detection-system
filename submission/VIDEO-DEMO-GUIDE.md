# Video demo — complete instructions, steps and commands

A full guide to recording the **3–5 minute demo video**. It runs entirely
**offline** from the 30 committed captures in `demo/` — no second machine, no
privileges, no network — and is **deterministic** (the engine clocks on packet
timestamps), so every take is identical. An optional live two-machine variant is
in Appendix B.

The video is a **standalone screen recording of the system running**. It does not
depend on the slide deck or its voiceover — those are a separate deliverable. Each
part below lists **every command to type** and **every key to press** (including
how to quit each screen), in order.

**Convention in this guide**
- Lines in a `sh` block are typed into the terminal, each followed by **Enter**.
- `Keys:` lines are single keypresses inside a full-screen view — press the key,
  do **not** press Enter.
- `Ctrl+C` means hold Ctrl and press C.

Suggested shape (≈4 min):

| Part | Time | What's on screen |
|---|---|---|
| A. Title card | 0:00–0:20 | A simple title card: project name, group no., members |
| B. All detectors fire | 0:20–1:20 | `demo/replay.sh` → 30/30 PASS table |
| C. Inside one alert | 1:20–2:10 | replay the SQLi capture, open the JSON |
| D. The kill-chain incident | 2:10–3:10 | replay capture 29, query the incident |
| E. Live dashboard | 3:10–3:50 | `demo/replay.sh --dashboard 29`, press `i`, `q` |
| F. Correctness + close | 3:50–4:15 | `go test -race`, end title card |

---

## 0. One-time prep (before recording)

Record at **1080p**, terminal font **16–18pt**, dark theme, window ≈120 columns.
Hide your home path in the prompt if it shows.

```sh
cd ~/projects/intrusion-detection-system

# 1. Build the binaries (needs libpcap-dev; a plain build is enough for replay)
make build                       # produces bin/ids and bin/capturedump

# 2. Start from a clean alert log so the demo isn't polluted by earlier runs
rm -f ids-alerts.jsonl /tmp/sqli.jsonl /tmp/kc.jsonl

# 3. Rehearse once — expect "30/30" so there are no surprises on the take
demo/replay.sh

# 4. Wipe the rehearsal output off the screen before you hit record
clear
```

`make build`, `rm`, `demo/replay.sh` and `clear` all finish on their own and
return you to the shell prompt — there is no key to press to exit them.

**Recording tool** — any of:
- `OBS Studio` (best for a polished video; title cards, optional webcam/voice).
- `asciinema rec demo.cast` then `agg demo.cast demo.gif` (crisp terminal capture).
  - To stop an `asciinema` recording: type `exit` + Enter, or press `Ctrl+D`.
- The OS screen recorder (GNOME Screencast / `Win+G` on Windows / QuickTime on macOS).

A title card can be a plain full-screen text slide, a terminal `clear` + a banner,
or a title image you cut in during editing — whatever your recorder makes easy.

---

## A. Title card — 0:00–0:20

Show project name, **Group No.**, and the six members. Then cut to a terminal.

```sh
ls demo/captures/        # 30 files scroll past — one per attack class
```

`ls` prints the list and returns to the prompt — nothing to exit.

---

## B. Every detector fires — 0:20–1:20

```sh
demo/replay.sh --list    # show the 30 captures and their headline sid (~3 s)
demo/replay.sh           # run them all; let the PASS table fill the screen
```

Both commands print their output and exit on their own. Hold on the final
**`30/30`** summary line for ~3 seconds.

> If the PASS table is taller than the screen and scrolls, pipe it through a pager
> to page through it on camera: `demo/replay.sh | less -R`. In `less`, press
> **Space** to page down, **`b`** to page up, and **`q`** to quit back to the shell.

---

## C. Inside one alert — 1:20–2:10

Open one alert so the viewer sees real evidence, not just a green table.

```sh
bin/ids run -no-tui -r demo/captures/14-web-sqli.pcap -rules rules.conf -log /tmp/sqli.jsonl
bin/ids query -log /tmp/sqli.jsonl -sid 1000210 -json
```

`-no-tui` makes `bin/ids run` process the capture, print its alerts, and return to
the shell (without it, `run` opens the full-screen dashboard — that is Part E). Both
commands above exit on their own; there is no key to press.

On screen, point at: the `sid` (1000210), `category` (web-attack), and the
**decoded** request line showing the UNION injection. Then the no-secrets one-liner:

```sh
bin/ids query -log /tmp/sqli.jsonl -sid 1000210
```

> If the `-json` output is long and scrolls, page it: `bin/ids query -log
> /tmp/sqli.jsonl -sid 1000210 -json | less -R` — **Space** pages down, **`q`** quits.

---

## D. The kill-chain incident — 2:10–3:10  *(the key moment)*

```sh
bin/ids run -no-tui -r demo/captures/29-incident-kill-chain.pcap -rules rules.conf -log /tmp/kc.jsonl
bin/ids query -log /tmp/kc.jsonl -kind incident -json
```

Both commands exit on their own. Show the single **incident** (sid 1001301) fusing
recon → exploit → C2 from one source.

---

## E. Live dashboard — 3:10–3:50

This is the **only** full-screen step. It opens a TUI that does **not** exit by
itself — you quit it with a keypress.

```sh
demo/replay.sh --dashboard 29
```

Once the dashboard is up, traffic is on the left, alerts on the right. Keys inside
the dashboard:

```
Keys (press the key, no Enter):
  i   toggle the Incidents panel  → press this to reveal the kill chain
  p   pause / resume the live feed
  r   reload rules
  q   quit the dashboard, back to the shell   (Ctrl+C also quits)
```

Suggested sequence on camera: let traffic flow for a moment → press **`i`** to show
the incidents panel (the kill chain appears) → press **`q`** to quit back to the
shell.

> If the replay runs too fast to film, record this segment separately and slow it
> to ~50% in your editor. Pressing **`p`** to pause also helps you line up a shot.

---

## F. Correctness + close — 3:50–4:15

```sh
go test -race ./...      # let it reach "ok" across the packages
make scenarios           # optional: show the 145-scenario pass count
```

Both run to completion and return to the prompt. If you need to abort either early
on camera, press **`Ctrl+C`**.

End on a closing title card (project name + "Thank you").

---

## Appendix A — command cheat-sheet (exact filming order)

Every typed command and every keypress, top to bottom:

```sh
# prep (not filmed)
make build
rm -f ids-alerts.jsonl /tmp/sqli.jsonl /tmp/kc.jsonl
demo/replay.sh                                            # expect 30/30
clear

# A
ls demo/captures/

# B
demo/replay.sh --list
demo/replay.sh

# C
bin/ids run -no-tui -r demo/captures/14-web-sqli.pcap -rules rules.conf -log /tmp/sqli.jsonl
bin/ids query -log /tmp/sqli.jsonl -sid 1000210 -json
bin/ids query -log /tmp/sqli.jsonl -sid 1000210

# D
bin/ids run -no-tui -r demo/captures/29-incident-kill-chain.pcap -rules rules.conf -log /tmp/kc.jsonl
bin/ids query -log /tmp/kc.jsonl -kind incident -json

# E  — full-screen dashboard
demo/replay.sh --dashboard 29
#   then, inside the dashboard, press:
#     i   (show Incidents panel)
#     q   (quit back to the shell; Ctrl+C also works)

# F
go test -race ./...
make scenarios
```

Pager keys, only if an output scrolls and you choose to pipe it through `less -R`:
**Space** = page down, **`b`** = page up, **`q`** = quit.

## Appendix B — optional live two-machine demo

For a more impressive "real network" segment, run the sensor on one host and the
lab-gated attack scripts from another. This needs two VMs (or two machines) on an
isolated segment and is documented fully in [`docs/DEMO.md`](../docs/DEMO.md)
(topologies, NIC-offload tuning, `make setcap`). The attack scripts refuse to run
without `--i-have-authorization` and a private target. Headline commands:

```sh
# sensor (victim) host — live capture + dashboard
bin/ids run -i eth0
#   this opens the same full-screen dashboard as Part E. Keys:
#     i = Incidents panel,  p = pause,  r = reload rules,  q = quit (Ctrl+C also quits)

# attacker host — e.g. the recon + web exploit + beacon kill chain
scripts/attacks/run-all.sh --i-have-authorization -t 192.168.56.20 --kill-chain
```

Only attempt the live demo on hardware you own and are authorized to test; the
offline replay above is sufficient for the submission and is far more reliable to
record.

## Recording tips

- Do one **silent dry-run** of the whole command order so there are no typos or
  `command not found` pauses on the take.
- Record the terminal and the dashboard as **separate clips** — the dashboard one
  you may want to slow down.
- Keep the alert-log files (`/tmp/*.jsonl`) on `/tmp` so they don't clutter the
  repo view on screen.
- If you ever get stuck on a full-screen view, **`q`** or **`Ctrl+C`** gets you back
  to the shell.
- Total runtime target **3–5 min**; if you're long, cut Part E first, then shorten
  Part F to just `go test -race ./...`.
```
