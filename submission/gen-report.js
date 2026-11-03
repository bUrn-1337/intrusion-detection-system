// Generates the project report as report.docx — Times New Roman 11pt, default margins.
const fs = require("fs");
const {
  Document, Packer, Paragraph, TextRun, HeadingLevel, AlignmentType,
  Table, TableRow, TableCell, WidthType, BorderStyle, ShadingType,
  PageBreak, TableOfContents, PositionalTab, PositionalTabAlignment,
  PositionalTabLeader,
} = require("docx");

const TNR = "Times New Roman";
const MONO = "Consolas";

// ---- small helpers -------------------------------------------------------
const P = (text, o = {}) =>
  new Paragraph({
    spacing: { after: o.after ?? 120, line: 276, ...(o.before ? { before: o.before } : {}) },
    alignment: o.align,
    indent: o.indent,
    children: [new TextRun({ text, bold: o.bold, italics: o.italics, size: o.size ?? 22, font: TNR })],
  });

// paragraph from runs: runs = [[text,{bold,italics,...}], ...]
const PR = (runs, o = {}) =>
  new Paragraph({
    spacing: { after: o.after ?? 120, line: 276 },
    alignment: o.align,
    children: runs.map(([t, ro = {}]) => new TextRun({ text: t, size: 22, font: TNR, ...ro })),
  });

const Bullet = (text, o = {}) =>
  new Paragraph({
    numbering: undefined,
    bullet: { level: o.level ?? 0 },
    spacing: { after: 80, line: 276 },
    children: (Array.isArray(text) ? text : [[text, {}]]).map(
      ([t, ro = {}]) => new TextRun({ text: t, size: 22, font: TNR, ...ro })
    ),
  });

const H1 = (text) =>
  new Paragraph({ text, heading: HeadingLevel.HEADING_1, spacing: { before: 280, after: 120 } });
const H2 = (text) =>
  new Paragraph({ text, heading: HeadingLevel.HEADING_2, spacing: { before: 200, after: 100 } });

// monospace figure in a single bordered cell
const Figure = (lines, caption) => {
  const border = { style: BorderStyle.SINGLE, size: 6, color: "888888" };
  const tbl = new Table({
    width: { size: 9360, type: WidthType.DXA },
    columnWidths: [9360],
    borders: { top: border, bottom: border, left: border, right: border,
      insideHorizontal: { style: BorderStyle.NONE }, insideVertical: { style: BorderStyle.NONE } },
    rows: [
      new TableRow({
        children: [
          new TableCell({
            width: { size: 9360, type: WidthType.DXA },
            shading: { type: ShadingType.CLEAR, fill: "F5F5F5" },
            margins: { top: 120, bottom: 120, left: 160, right: 160 },
            children: lines.map(
              (l) =>
                new Paragraph({
                  spacing: { after: 0, line: 240 },
                  children: [new TextRun({ text: l.length ? l : " ", font: MONO, size: 15 })],
                })
            ),
          }),
        ],
      }),
    ],
  });
  const cap = new Paragraph({
    spacing: { before: 60, after: 160 },
    alignment: AlignmentType.CENTER,
    children: [new TextRun({ text: caption, italics: true, size: 18, font: TNR })],
  });
  return [tbl, cap];
};

// placeholder box for a screenshot the team pastes in
const ShotPlaceholder = (caption) => {
  const border = { style: BorderStyle.DASHED, size: 8, color: "999999" };
  const tbl = new Table({
    width: { size: 9360, type: WidthType.DXA },
    columnWidths: [9360],
    borders: { top: border, bottom: border, left: border, right: border,
      insideHorizontal: { style: BorderStyle.NONE }, insideVertical: { style: BorderStyle.NONE } },
    rows: [
      new TableRow({
        children: [
          new TableCell({
            width: { size: 9360, type: WidthType.DXA },
            margins: { top: 360, bottom: 360, left: 160, right: 160 },
            children: [
              new Paragraph({
                alignment: AlignmentType.CENTER,
                spacing: { after: 0 },
                children: [new TextRun({ text: "[ paste screenshot here ]", italics: true, color: "999999", size: 20, font: TNR })],
              }),
            ],
          }),
        ],
      }),
    ],
  });
  const cap = new Paragraph({
    spacing: { before: 60, after: 160 },
    alignment: AlignmentType.CENTER,
    children: [new TextRun({ text: caption, italics: true, size: 18, font: TNR })],
  });
  return [tbl, cap];
};

// generic table builder: header[], rows[][], widths[] summing to 9360
function makeTable(header, rows, widths) {
  const total = widths.reduce((a, b) => a + b, 0);
  const b = { style: BorderStyle.SINGLE, size: 4, color: "BBBBBB" };
  const borders = { top: b, bottom: b, left: b, right: b, insideHorizontal: b, insideVertical: b };
  const cell = (txt, i, opts = {}) =>
    new TableCell({
      width: { size: widths[i], type: WidthType.DXA },
      shading: opts.head ? { type: ShadingType.CLEAR, fill: "1F3864" } : (opts.zebra ? { type: ShadingType.CLEAR, fill: "EEF2F8" } : undefined),
      margins: { top: 40, bottom: 40, left: 80, right: 80 },
      children: [
        new Paragraph({
          spacing: { after: 0, line: 240 },
          children: (Array.isArray(txt) ? txt : [[txt, {}]]).map(
            ([t, ro = {}]) =>
              new TextRun({ text: t, size: 19, font: TNR, bold: opts.head || ro.bold, color: opts.head ? "FFFFFF" : ro.color, italics: ro.italics })
          ),
        }),
      ],
    });
  return new Table({
    width: { size: total, type: WidthType.DXA },
    columnWidths: widths,
    borders,
    rows: [
      new TableRow({ tableHeader: true, children: header.map((h, i) => cell(h, i, { head: true })) }),
      ...rows.map((r, ri) => new TableRow({ children: r.map((c, i) => cell(c, i, { zebra: ri % 2 === 1 })) })),
    ],
  });
}

// ---- cover page ----------------------------------------------------------
const cover = [
  P("[ Institute / Department Name ]", { align: AlignmentType.CENTER, bold: true, size: 24, after: 60 }),
  P("[ Course Code — Course Name ]", { align: AlignmentType.CENTER, size: 22, after: 400 }),
  P("Project Report", { align: AlignmentType.CENTER, italics: true, size: 26, after: 120 }),
  P("A Network Intrusion Detection System with", { align: AlignmentType.CENTER, bold: true, size: 40, after: 0 }),
  P("Spoof-Resistant Attack Correlation", { align: AlignmentType.CENTER, bold: true, size: 40, after: 120 }),
  P("(built from scratch in Go — own packet pipeline, declarative rule engine, live dashboard)",
    { align: AlignmentType.CENTER, italics: true, size: 22, after: 400 }),
  PR([["Group No.: ", {}], ["________", { bold: true }]], { align: AlignmentType.CENTER, size: 24, after: 300 }),
  P("Submitted by", { align: AlignmentType.CENTER, italics: true, after: 160 }),
];

// team table: Name | Enrol | Title | Mobile | Email
const team = [
  ["Aditya Pratap Singh Bhadoria", "24114005"],
  ["Aditya Ranjan", "24114006"],
  ["Daddi Om Santosh", "24114028"],
  ["Deokar Parth Rajesh", "24114032"],
  ["Kothawade Manthan", "24114050"],
  ["Satyam Sharma", "24114088"],
];
const teamTable = makeTable(
  ["Name", "Enrolment", "Title", "Mobile no.", "Email ID"],
  team.map(([n, e]) => [n, e, "____", "+91-__________", "__________@____"]),
  [3000, 1360, 900, 2000, 2100]
);

// individual-contribution table (one row per member)
const contrib = [
  ["Aditya Pratap Singh Bhadoria", "24114005",
    "Upper-layer parser (TCP/UDP/ICMP) and the TCP stream-reassembly stage — handshake table, application-port flows and overlap-conflict handling that underpins evasion resistance. Built the scan and volumetric-flood detectors: vertical/horizontal scans (1000401/1000402) and SYN/UDP/ICMP/LAND floods (1000001/1000012/1000022/1000003)."],
  ["Aditya Ranjan", "24114006",
    "Application parsers (HTTP, DNS, FTP, TLS/JA3) and the web and DNS detectors: SQLi, XSS, path traversal, command injection, Log4Shell, Shellshock (1000210–1000223, incl. the overlong-UTF-8 URI normaliser), FTP brute force (1000301), and DNS zone-transfer / amplification / tunnel / DGA signatures (1000101–1000110)."],
  ["Daddi Om Santosh", "24114028",
    "Capture engine (live AF_PACKET/pcap + .pcap replay, snaplen/promiscuous handling, the capture ring with its drop-vs-wait policy and drop accounting) and the whole output side — the rotating JSONL logger and the live terminal dashboard with rolling top-N tables and pause/resume."],
  ["Deokar Parth Rajesh", "24114032",
    "Lower-layer parser — Ethernet, VLAN walking, IPv4/IPv6 with the extension-header chain and fragmentation fields, and ARP. Built the detectors keyed on those layers: teardrop (1000701) and ping-of-death (1000703), ARP cache-poisoning (1000802–1000804), and the IP TTL-anomaly spoofing check (1000601)."],
  ["Kothawade Manthan", "24114050",
    "Threat-intel matching (IP/domain/JA3 feeds, 1001001–1001003) and the behavioural detectors — periodic C2 beaconing (1001101) and the statistical host-fanout baseline/anomaly (1001201) — plus the entropy engine behind DGA/tunnel scoring, and the test harness: the scenario runner and its 145 fixtures, the fuzz targets, the false-positive corpus and CI."],
  ["Satyam Sharma", "24114088",
    "The detection core — the rule engine and rule language, the stateful-detector framework every other detector plugs into, the packet-time deterministic clock, and the spoofable-vs-reliable attribution model. Owns correlation and incident construction — the multi-stage kill-chain and callback logic (1001301/1001303) with its framing resistance."],
];
const contribTable = makeTable(
  ["Member", "Enrol.", "Primary individual contribution"],
  contrib,
  [2500, 1000, 5860]
);

// ---- figures -------------------------------------------------------------
const pipeline = [
  " [ libpcap capture ]        live interface  OR  .pcap file",
  "        |  copy each frame into a new ParsedPacket",
  "        v",
  " [ bounded queue : 10000 ]  live: drop-when-full | file: wait",
  "        v",
  " [ lower parse ]            Ethernet, VLAN, IPv4 / IPv6, ARP",
  "        v",
  " [ upper parse ]            TCP, UDP, ICMP  (+ checksum status)",
  "        v",
  " [ stream reassembly ]      TCP on app ports -> whole messages",
  "        v",
  " [ app parse ]             HTTP, DNS, FTP, TLS ClientHello / JA3",
  "        v",
  " [ rule engine ]           detectors -> attribution -> correlation",
  "        |",
  "        +---> JSON Lines alert log  (size-rotating)",
  "        +---> live dashboard (TUI)  +  traffic counters",
];

const dashFig = [
  "┌ Incidents (2 active) ─────────────────────────────────────────┐",
  "│ SEV        SCORE KIND          ENTITY               STAGES     │",
  "│ [critical]    27 multi_stage   203.0.113.9->10.0.0.80 recon->  │",
  "│                                                   exploit->c2  │",
  "│ [critical]    18 compromised_h 10.0.0.80           exploit->c2 │",
  "└───────────────────────────────────────────────────────────────┘",
  "┌ Traffic ──────────────────┐┌ Capture health ──────────────────┐",
  "│ Packets/s     58.33k      ││ Captured             634          │",
  "│ Bytes/s     4.87 MiB      ││ Kernel drops           0          │",
  "│ Packets          634      ││ Queue drops            0          │",
  "│ Alerts            43      ││ Stream evictions       0          │",
  "└───────────────────────────┘└───────────────────────────────────┘",
];

const queryFig = [
  "$ ids query -log ids-alerts.jsonl -kind incident",
  "TIME                 KIND     SEV      SID     SOURCE       DEST",
  "2026-..T12:10:00.215Z incident high    1001301 203.0.113.9  10.0.0.80",
  "  Multi-stage attack  (recon -> exploit -> c2)",
  "",
  "$ ids query -log ids-alerts.jsonl -severity critical",
  "2026-..T12:10:00.215Z alert    critical 1000221 203.0.113.9  10.0.0.80",
  "  Log4Shell JNDI lookup in HTTP header",
];

// ---- comparison table ----------------------------------------------------
const cmp = makeTable(
  ["Aspect", "This project", "Snort 3", "Suricata", "Zeek"],
  [
    ["Primary model", "Signature + stateful behavioural + cross-alert correlation", "Signature (rule-based)", "Signature + limited anomaly", "Protocol analysis + scripting"],
    ["Implementation", "Go, single-threaded parse/match core", "C / C++", "C (multi-threaded)", "C++ + Zeek script"],
    ["Packet pipeline", "Hand-written parsers, one shared ParsedPacket", "DAQ + decoders", "Decoders + flow engine", "Event-driven analysers"],
    ["Rule language", "Custom declarative rules.conf (RE2 regex)", "Snort rules (PCRE)", "Suricata/Snort rules (PCRE)", "No signatures; Zeek script"],
    ["Spoof-aware attribution", [["Yes — every alert tagged reliable vs spoofable", { bold: true }]], "No", "No", "Partial (via scripting)"],
    ["Correlation / incidents", [["Built-in, spoof-resistant kill chains", { bold: true }]], "Via add-ons / SIEM", "Via SIEM", "Via scripts / SIEM"],
    ["Deterministic replay", [["Yes — packet-time clock", { bold: true }]], "No (wall-clock state)", "No", "Mostly"],
    ["Bounded memory under flood", "Yes — fixed-size tables, LRU eviction", "Tunable", "Tunable", "Tunable"],
    ["ReDoS safety", "Yes — RE2, linear time", "No (PCRE backtracking)", "No (PCRE)", "n/a"],
    ["Maturity / scale", "Educational, ~42k LOC", "Production, very large", "Production, very large", "Production, very large"],
  ],
  [1640, 2360, 1800, 1800, 1760]
);

const refs = [
  "The gopacket / libpcap packet-capture library. https://github.com/gopacket/gopacket",
  "rivo/tview and gdamore/tcell terminal-UI libraries. https://github.com/rivo/tview",
  "S. McCanne and V. Jacobson, \"The BSD Packet Filter: A New Architecture for User-level Packet Capture,\" USENIX, 1993.",
  "M. Roesch, \"Snort — Lightweight Intrusion Detection for Networks,\" Proc. LISA, 1999.",
  "Open Information Security Foundation, Suricata IDS/IPS. https://suricata.io",
  "V. Paxson, \"Bro: A System for Detecting Network Intruders in Real-Time\" (Zeek), Computer Networks, 1999.",
  "S. Bellovin, \"Security Problems in the TCP/IP Protocol Suite,\" ACM CCR, 1989. (IP spoofing / framing.)",
  "T. Ptacek and T. Newsham, \"Insertion, Evasion, and Denial of Service: Eluding Network Intrusion Detection,\" 1998.",
  "J. Postel, RFC 791 (IP), RFC 793 (TCP); S. Deering and R. Hinden, RFC 8200 (IPv6). IETF.",
  "R. Elz and R. Bush, RFC 1982, \"Serial Number Arithmetic.\" IETF, 1996.",
  "J. Althouse et al., \"JA3 — a method for profiling SSL/TLS clients,\" Salesforce Engineering, 2017.",
  "Mozilla / Public Suffix List. https://publicsuffix.org",
  "R. Russ, \"RE2 — a regular expression engine with linear-time guarantees.\" https://github.com/google/re2",
  "MITRE ATT&CK framework (kill-chain stages). https://attack.mitre.org",
];

// ---- document assembly ---------------------------------------------------
const body = [];
body.push(...cover);
body.push(teamTable);
body.push(P("", { after: 200 }));
body.push(P("Individual contribution", { bold: true, align: AlignmentType.CENTER, after: 120 }));
body.push(contribTable);
body.push(new Paragraph({ children: [new PageBreak()] }));

// TOC
body.push(P("Table of Contents", { bold: true, size: 28, after: 160 }));
body.push(new TableOfContents("Contents", { hyperlink: true, headingStyleRange: "1-2" }));
body.push(new Paragraph({ children: [new PageBreak()] }));

// 1. Introduction
body.push(H1("1. Introduction"));
body.push(H2("1.1 Background"));
body.push(P("A network intrusion detection system (IDS) watches the traffic on a network segment and raises an alert when it sees evidence of an attack. Unlike a firewall, which decides whether a packet is allowed, an IDS is a passive observer: it reconstructs what is happening on the wire and judges it. Two broad approaches exist. A signature IDS matches traffic against known-bad patterns (a SQL-injection string, a port-scan shape); an anomaly IDS learns what normal traffic looks like and flags deviations. Production systems such as Snort, Suricata and Zeek combine capture, protocol decoding, a detection engine and alert output into one pipeline."));
body.push(P("This project implements such a pipeline end to end, in Go, without using an existing detection engine. Every layer — from pulling frames off the wire to deciding that three alerts are one attacker's kill chain — is our own code."));
body.push(H2("1.2 Motivation"));
body.push(P("Off-the-shelf rule sets detect individual events well but leave two problems to the operator. First, they emit alerts, not incidents: a real attack produces a recon scan, an exploit and a callback as separate, un-linked alerts, and a human (or a downstream SIEM) must stitch them together. Second, and more subtly, most engines attribute an alert to the source IP address in the packet — but that address is trivially forged for UDP, ICMP and spoofed SYN floods. An attacker can therefore spoof a victim's address into flood traffic and make the IDS blame the victim. We wanted to build a system that treats source attribution as a first-class, trust-rated property and that correlates alerts into incidents without ever letting forged traffic frame an innocent host."));
body.push(H2("1.3 Application domain"));
body.push(P("The system targets the security-monitoring of a small-to-medium network segment: a sensor placed at a victim host, on a SPAN/mirror port, or inline on an isolated lab segment. It is useful for perimeter and lab monitoring, for teaching how attacks look on the wire, and as a reproducible research harness — because detection is driven entirely by packet timestamps, replaying a capture yields exactly the same alerts every time, which production IDSs (keyed on wall-clock state) do not guarantee. The attack classes it detects — reconnaissance, denial-of-service, spoofing, web exploitation, DNS abuse, command-and-control and multi-stage intrusions — cover the common stages of the MITRE ATT&CK kill chain."));

// 2. Proposed system
body.push(H1("2. Proposed System"));
body.push(P("The system is a six-stage pipeline. A capture source produces raw frames; four parsing stages decode them into a single shared structure; a rule engine detects attacks, rates the trustworthiness of each alert's attribution, and correlates alerts into incidents; and an output stage writes a rotating JSON-Lines log and drives a live terminal dashboard."));
body.push(...Figure(pipeline, "Figure 1 — The detection pipeline. Each stage writes fields of one shared ParsedPacket; later stages only read earlier fields."));
body.push(H2("2.1 The shared ParsedPacket contract"));
body.push(P("The six modules communicate through exactly one data structure, ParsedPacket. Each field is written by exactly one stage and read only by later stages, and a stage never rejects a packet — it fills in what it could decode and records problems as structured reasons. This contract is what lets six people develop six modules independently: the interface between any two stages is a documented set of fields, not a function call."));
body.push(H2("2.2 Stage design (steps of the system)"));
body.push(Bullet([["Capture. ", { bold: true }], ["Reads from a live interface (promiscuous, 262 KB snaplen) or a .pcap file. A bounded queue decouples capture from processing: a live capture drops when the queue is full (and counts the drop), while a file replay waits, so no packet is ever silently lost on replay."]]));
body.push(Bullet([["Lower-layer parse. ", { bold: true }], ["Ethernet and VLAN tags, IPv4 and IPv6 (including the IPv6 extension-header chain), and ARP. Fragmentation ranges are recorded but never reassembled."]]));
body.push(Bullet([["Upper-layer parse. ", { bold: true }], ["TCP, UDP and ICMP/ICMPv6, with transport-checksum verification recorded (but never alerted on, because checksum offload makes locally-sent checksums unreliable)."]]));
body.push(Bullet([["Stream reassembly. ", { bold: true }], ["A single bounded stage reassembles TCP on the application ports and hands the application parsers whole messages. It buffers only the message in progress, uses RFC 1982 serial arithmetic for sequence numbers, and evicts least-recently-used flows past a fixed memory budget so a flood cannot exhaust memory."]]));
body.push(Bullet([["Application parse. ", { bold: true }], ["HTTP, DNS, FTP and the TLS ClientHello (for JA3 fingerprinting). URIs are canonicalised — percent-decoding and overlong-UTF-8 folding — so an attacker cannot hide a payload behind encoding."]]));
body.push(Bullet([["Rule engine. ", { bold: true }], ["Loads a declarative rule file, runs signature and stateful detectors, assigns each alert a trust-rated attribution, and correlates alerts into incidents. Output goes to a rotating JSONL log and the dashboard."]]));
body.push(H2("2.3 The rule language"));
body.push(P("Detections are not hard-coded; they are declared in rules.conf (89 rules and 3 threat-intel feeds in the shipped configuration). A rule names a signature id, the protocol and condition it matches, a severity, a category, and the attack-chain stage it belongs to. Rules load at start-up and hot-reload on demand without dropping capture. Regular expressions compile with Go's RE2 engine, which runs in time linear in the input, so a crafted request cannot force seconds of backtracking (the ReDoS problem that affects PCRE-based engines)."));
body.push(H2("2.4 Novelty — trust-rated attribution and spoof-resistant correlation"));
body.push(P("The central idea of the project is that a source IP address is only evidence when the sender had to receive a reply to get that far. Every alert therefore carries an attribution of either reliable or spoofable, decided by how it was detected:"));
body.push(makeTable(
  ["Attribution", "When", "Why it is trustworthy (or not)"],
  [
    [[["reliable", { bold: true }]], "Alert needs a completed TCP handshake or a reassembled stream (web attacks, DNS over TCP, slowloris, beacons); ARP spoofing keyed on sender MAC", "The source had to answer a SYN-ACK or be the real L2 sender — it cannot be a one-packet forgery"],
    [[["spoofable", { bold: true }]], "Alert from a single UDP/ICMP packet, a lone SYN, or per-packet IP header fields (floods, scans, reflection, TTL anomaly, baseline)", "One forged packet is enough to trigger it, so the named source may be a victim, not the attacker"],
  ],
  [1700, 3860, 3800]
));
body.push(P("Correlation builds on this. Every alert is added to the history of its source (as attacker) and destination (as victim). Incident rules then look for a kill chain — recon, then exploit, then callback — from one source. The rule is strict: a spoofable alert never names an attacker. A UDP flood forged to look like it comes from host Z adds to Z's victim history, but an incident naming Z as the attacker requires Z to have a reliable alert of its own against that victim. This is what makes the correlation framing-resistant: an attacker cannot spoof an innocent host into being accused of an intrusion. A dedicated test (the spoofed_framing scenario) asserts exactly this."));
body.push(H2("2.5 Supporting algorithms"));
body.push(Bullet([["Packet-time clock. ", { bold: true }], ["The engine's clock is the packet timestamp, never the wall clock, and never moves backward (now = max(now, packet.time)). This makes replay deterministic and immune to the clock steps a virtualised sensor suffers."]]));
body.push(Bullet([["Scan vs. flood by handshake outcome. ", { bold: true }], ["Both begin as incomplete handshakes; a flood hits few ports at high rate, a scan hits many ports. A SYN is judged a probe by its handshake's outcome, not on sight, so a busy browser is not mistaken for a scanner."]]));
body.push(Bullet([["A flood is traffic that is not answered. ", { bold: true }], ["Rate alone cannot separate a UDP flood from a video call, so the detector also measures the reply ratio and fires only when almost nothing is answered — which also works when every source is spoofed (the by_dst track)."]]));
body.push(Bullet([["Beacons by median interval; baselines by absolute deviation. ", { bold: true }], ["C2 beaconing is found from the median of recent connection intervals (robust to missed beats); the host-fanout baseline scores deviations against an exponentially-weighted absolute deviation rather than variance, so one burst does not blind it."]]));
body.push(Bullet([["Bounded tables. ", { bold: true }], ["Every piece of engine state lives in a fixed-size table with LRU eviction, so memory stays flat under attack — one million spoofed-source SYNs peak at 176 MB and evict cleanly rather than exhausting the host."]]));

// 3. Implementation
body.push(H1("3. Implementation"));
body.push(H2("3.1 Tools and technology"));
body.push(Bullet([["Language: ", { bold: true }], ["Go 1.27 (single-threaded parse/match core; separate goroutines only for capture and log writing, joined by channels)."]]));
body.push(Bullet([["Capture: ", { bold: true }], ["gopacket / libpcap for live and file capture."]]));
body.push(Bullet([["Dashboard: ", { bold: true }], ["rivo/tview and gdamore/tcell for the terminal UI."]]));
body.push(Bullet([["Standard library: ", { bold: true }], ["Go's RE2 regexp engine; golang.org/x/net/publicsuffix for grouping DNS queries by registered domain."]]));
body.push(Bullet([["Scale: ", { bold: true }], ["about 42,000 lines of Go across 115 files and ~20 packages; 89 rules and 3 feeds shipped."]]));
body.push(Bullet([["Testing: ", { bold: true }], ["unit tests per package, 145 end-to-end scenarios, fuzz targets on every parser, and a false-positive corpus — all run under the Go race detector in CI."]]));
body.push(H2("3.2 Module ownership"));
body.push(makeTable(
  ["Area", "Primary owner", "Packages"],
  [
    ["Capture, logging & dashboard", "Daddi Om Santosh", "capture, logging, logging/tui"],
    ["Lower-layer parsers + frag/ARP detectors", "Deokar Parth Rajesh", "parser/lower"],
    ["Upper-layer parsers, stream reassembly + scan/flood", "Aditya Pratap Singh Bhadoria", "parser/upper, stream"],
    ["Application parsers + web/DNS detectors", "Aditya Ranjan", "parser/app"],
    ["Rule engine, rule language + correlation/incidents", "Satyam Sharma", "rules"],
    ["Threat-intel feeds, behavioural detectors + test harness", "Kothawade Manthan", "intel, entropy, scenarios/fuzz/CI"],
  ],
  [4000, 2760, 2600]
));
body.push(H2("3.3 Detection coverage"));
body.push(P("The shipped configuration detects, among others: reconnaissance (vertical and horizontal scans), denial-of-service (SYN/UDP/ICMP floods, LAND, Smurf, Slowloris, RUDY), evasion (teardrop, ping-of-death), spoofing (ARP cache poisoning, TTL anomaly), web exploitation (SQL injection, XSS, path traversal, command injection, Log4Shell, Shellshock), DNS abuse (zone transfer, amplification, tunnelling, DGA/NXDOMAIN bursts), credential attacks (FTP brute force), threat-intel feed hits (IP, domain, JA3), command-and-control beaconing, statistical anomalies, and two classes of correlated multi-stage incident. A committed set of 30 captures — one per class — is replayed by demo/replay.sh, which confirms each detector still fires."));
body.push(H2("3.4 Screenshots of the system"));
body.push(P("The live dashboard shows traffic rates, capture health, protocol mix, top talkers, the alert stream and an incidents panel. Figure 2 is a representative view while replaying the kill-chain capture; Figure 3 shows querying the alert log afterwards. (Teams should replace these with full-colour screenshots captured during the live demo.)"));
body.push(...Figure(dashFig, "Figure 2 — Live dashboard: two correlated incidents built from one attacker, with traffic and capture-health panels."));
body.push(...ShotPlaceholder("Figure 2a — (optional) full-screen colour screenshot of the live TUI dashboard."));
body.push(...Figure(queryFig, "Figure 3 — Querying the alert log: the correlated incident and the critical alert behind it."));
body.push(P("Credentials are never shown: HTTP Authorization headers and FTP passwords are redacted at parse time and never written to the log or the screen.", { italics: true }));
body.push(H2("3.5 Comparison with existing systems"));
body.push(P("The table compares this project with three widely-used open-source IDSs. The intent is not to claim parity in scale or maturity — those are large production systems and this is an educational implementation — but to show where the design choices differ, particularly the trust-rated attribution and built-in spoof-resistant correlation, which the mainstream engines leave to a downstream SIEM."));
body.push(cmp);
body.push(H2("3.6 Validation results"));
body.push(Bullet("Correctness: the full suite passes under the race detector; 145 end-to-end scenarios pass; every parser is fuzzed (two malformed-input defects found and fixed, kept as regression seeds)."));
body.push(Bullet("All 30 demonstration captures fire their expected detector or incident (30/30)."));
body.push(Bullet("A benign false-positive corpus of ~24,000 packets raises zero alerts and zero incidents."));
body.push(Bullet("Throughput ~283k packets/s (~25.7 Gbit/s peak) in replay benchmarks; a 60-minute soak sustained ~219k packets/s over 811 million packets with zero drops, zero evictions and no memory growth."));

// 4. Conclusion
body.push(H1("4. Conclusion"));
body.push(P("We built a complete network intrusion detection system from scratch in Go: its own packet-capture path, four hand-written parsing stages, a declarative rule engine with 89 rules, and a live dashboard — about 42,000 lines of code developed by six people against one shared packet contract. The system detects the full range of common attack classes and, crucially, goes beyond per-event alerting."));
body.push(P("Its distinguishing contribution is treating source attribution as a trust-rated property. By labelling every alert reliable or spoofable and building incidents only from reliable attackers, the system correlates a recon-exploit-callback kill chain into a single incident while provably refusing to let a spoofed source frame an innocent host — a failure mode that ordinary source-IP attribution is open to. Combined with a deterministic packet-time clock, bounded memory under flood, and RE2's linear-time matching, the result is an IDS that is reproducible, resource-safe and resistant to both evasion and framing."));
body.push(P("Limitations remain and are documented honestly in the architecture notes: encrypted DNS (DoH/DoT) is opaque, a single-direction (asymmetric) capture confuses the scan detectors, an adaptive baseline can be slowly \"boiled,\" and unicast ARP poisoning is invisible off a mirror port. Natural future work is a second slow reference baseline to defeat the boiling-frog ramp, IP-level reassembly for cross-fragment content matching, and export of incidents to a standard SIEM format."));

// 5. Bibliography
body.push(H1("5. Bibliography"));
refs.forEach((r, i) => body.push(P(`[${i + 1}] ${r}`, { after: 80 })));

// ---- styles & doc --------------------------------------------------------
const doc = new Document({
  creator: "IDS project group",
  title: "IDS Project Report",
  styles: {
    default: {
      document: { run: { font: TNR, size: 22 } },
      heading1: { run: { font: TNR, size: 30, bold: true, color: "1F3864" }, paragraph: { spacing: { before: 280, after: 120 }, keepNext: true } },
      heading2: { run: { font: TNR, size: 25, bold: true, color: "2E5496" }, paragraph: { spacing: { before: 200, after: 100 }, keepNext: true } },
    },
    paragraphStyles: [
      { id: "Normal", name: "Normal", run: { font: TNR, size: 22 }, paragraph: { spacing: { line: 276, after: 120 } } },
    ],
  },
  sections: [
    {
      properties: {},
      children: body,
    },
  ],
});

Packer.toBuffer(doc).then((buf) => {
  fs.writeFileSync(__dirname + "/report.docx", buf);
  console.log("wrote report.docx (" + buf.length + " bytes)");
});
