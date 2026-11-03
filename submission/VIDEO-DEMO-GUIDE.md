# Video demo — complete instructions, steps and commands

A full guide to recording the **3–5 minute demo video**. It runs entirely
**offline** from the 30 committed captures in `demo/` — no second machine, no
privileges, no network — and is **deterministic** (the engine clocks on packet
timestamps), so every take is identical. An optional live two-machine variant is
in Appendix B.

Suggested shape of the video (≈4 min):

| Part | Time | What's on screen |
|---|---|---|
| A. Title + what it is | 0:00–0:30 | Title slide (from `slides.pptx`) with group no. + members |
| B. All detectors fire | 0:30–1:30 | `demo/replay.sh` → 30/30 PASS table |
| C. Inside one alert | 1:30–2:15 | replay the SQLi capture, open the JSON |
| D. The kill-chain incident | 2:15–3:15 | replay capture 29, query the incident; the framing point |
| E. Live dashboard | 3:15–3:50 | `demo/replay.sh --dashboard 29`, press `i`, `q` |
| F. Correctness + close | 3:50–4:15 | `go test -race`, back to title slide |

> You do **not** narrate from this file. The spoken narration is the speaker
> notes in `slides.pptx` (one block per slide). Record the voiceover from those;
> use this file to drive the **screen**.

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
clear
```

**Recording tool** — any of:
- `OBS Studio` (best for a polished video; lets you add the slide intro and your webcam/voice).
- `asciinema rec demo.cast` then `agg demo.cast demo.gif` (crisp terminal, but no audio — pair with slides for voiceover).
- The OS screen recorder (GNOME Screencast / `Win+G` on Windows / QuickTime on macOS).

If you want the **slide intro + voiceover** in the same file: export `slides.pptx`
to a narrated video (PowerPoint: *File → Export → Create a Video* after recording
narration on the slides; LibreOffice: record separately and stitch in your editor),
then concatenate the slide clip and the terminal clip.

---

## A. Title — 0:00–0:30

Show the **title slide** of `slides.pptx` (group number + all six members). If you
recorded slide narration, this is slide 1's voiceover. Then cut to a terminal.

```sh
ls demo/captures/        # 30 files scroll past — one per attack class
```

---

## B. Every detector fires — 0:30–1:30

```sh
demo/replay.sh --list    # show the 30 captures and their headline sid (~3 s)
demo/replay.sh           # run them all; let the PASS table fill the screen
```

Hold on the final **`30/30`** summary line for ~3 seconds. (Narration: slide 6.)

---

## C. Inside one alert — 1:30–2:15

Open one alert so the audience sees real evidence, not just a green table.

```sh
bin/ids run   -r demo/captures/14-web-sqli.pcap -rules rules.conf -log /tmp/sqli.jsonl
bin/ids query -log /tmp/sqli.jsonl -sid 1000210 -json
```

On screen, point at: the `sid` (1000210), `category` (web-attack), and the
**decoded** request line showing the UNION injection. Then show the no-secrets
one-liner:

```sh
bin/ids query -log /tmp/sqli.jsonl -sid 1000210
```

(Narration: slide 4 / slide 7 — decoding defeats encoding evasion; credentials
are never logged.)

---

## D. The kill-chain incident — 2:15–3:15  *(the key moment)*

```sh
bin/ids run   -r demo/captures/29-incident-kill-chain.pcap -rules rules.conf -log /tmp/kc.jsonl
bin/ids query -log /tmp/kc.jsonl -kind incident -json
```

Show the single **incident** (sid 1001301) fusing recon → exploit → C2 from one
source. (Narration: slide 5 — a spoofed source cannot manufacture an incident;
the `spoofed_framing` test proves it.)

---

## E. Live dashboard — 3:15–3:50

```sh
demo/replay.sh --dashboard 29
```

In the TUI: traffic on the left, alerts on the right. Press **`i`** to reveal the
incidents panel (the kill chain appears), then **`q`** to quit.

> If the replay runs too fast to film, record this segment separately and slow it
> to ~50% in your editor. (Narration: slide 7.)

---

## F. Correctness + close — 3:50–4:15

```sh
go test -race ./...      # let it reach "ok" across the packages
make scenarios           # optional: show the 145-scenario pass count
```

Cut back to the **closing slide** (slide 10) of `slides.pptx`. (Narration: slide
9 stats + slide 10 conclusion.)

---

## Appendix A — command cheat-sheet (exact filming order)

```sh
# prep (not filmed)
make build
rm -f ids-alerts.jsonl /tmp/sqli.jsonl /tmp/kc.jsonl
demo/replay.sh                                            # expect 30/30

# B
demo/replay.sh --list
demo/replay.sh

# C
bin/ids run   -r demo/captures/14-web-sqli.pcap -rules rules.conf -log /tmp/sqli.jsonl
bin/ids query -log /tmp/sqli.jsonl -sid 1000210 -json
bin/ids query -log /tmp/sqli.jsonl -sid 1000210

# D
bin/ids run   -r demo/captures/29-incident-kill-chain.pcap -rules rules.conf -log /tmp/kc.jsonl
bin/ids query -log /tmp/kc.jsonl -kind incident -json

# E  (press i, then q)
demo/replay.sh --dashboard 29

# F
go test -race ./...
make scenarios
```

## Appendix B — optional live two-machine demo

For a more impressive "real network" segment, run the sensor on one host and the
lab-gated attack scripts from another. This needs two VMs (or two machines) on an
isolated segment and is documented fully in [`docs/DEMO.md`](../docs/DEMO.md)
(topologies, NIC-offload tuning, `make setcap`). The attack scripts refuse to run
without `--i-have-authorization` and a private target. Headline commands:

```sh
# sensor (victim) host — live capture + dashboard
bin/ids run -i eth0

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
- Total runtime target **3–5 min**; if you're long, cut Part E first, then shorten
  Part F to just `go test -race ./...`.
```
