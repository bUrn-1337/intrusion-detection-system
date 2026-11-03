// Generates slides.pptx — presentation deck with per-slide voiceover in speaker notes.
const pptxgen = require("pptxgenjs");
const p = new pptxgen();
p.layout = "LAYOUT_WIDE"; // 13.33 x 7.5
p.author = "IDS project group";
p.title = "IDS Project — Spoof-Resistant Intrusion Detection";

// palette
const NAVY = "0E2142", NAVY2 = "17315A", TEAL = "22B8A6", TEALD = "0E7C70";
const ICE = "CFE0F2", INK = "1B2A41", GRAY = "5E6E85", WHITE = "FFFFFF", CARD = "F2F6FC", LINE = "D9E2EF";
const HEAD = "Cambria", BODY = "Calibri";
const W = 13.33, H = 7.5;

const tb = (o) => ({ isTextBox: true, margin: 0, ...o });

function titleBar(slide, text, kicker) {
  if (kicker) slide.addText(kicker.toUpperCase(), tb({ x: 0.7, y: 0.45, w: 12, h: 0.35, fontFace: BODY, fontSize: 13, bold: true, color: TEALD, charSpacing: 2 }));
  slide.addText(text, tb({ x: 0.7, y: 0.74, w: 12, h: 0.8, fontFace: HEAD, fontSize: 30, bold: true, color: NAVY }));
}

// circle + icon-ish glyph helper (use a shape + letter, no external icons)
function chip(slide, x, y, glyph, fill) {
  slide.addShape(p.ShapeType.ellipse, { x, y, w: 0.52, h: 0.52, fill: { color: fill }, line: { type: "none" } });
  slide.addText(glyph, tb({ x, y, w: 0.52, h: 0.52, align: "center", valign: "middle", fontFace: BODY, fontSize: 18, bold: true, color: WHITE }));
}

// ---------- Slide 1: title (dark) ----------
let s = p.addSlide();
s.background = { color: NAVY };
s.addShape(p.ShapeType.ellipse, { x: 10.6, y: -1.5, w: 4.5, h: 4.5, fill: { color: NAVY2 }, line: { type: "none" } });
s.addShape(p.ShapeType.ellipse, { x: -1.3, y: 5.2, w: 3.6, h: 3.6, fill: { color: NAVY2 }, line: { type: "none" } });
s.addText("NETWORK INTRUSION DETECTION", tb({ x: 0.9, y: 1.5, w: 11.5, h: 0.4, fontFace: BODY, fontSize: 15, bold: true, color: TEAL, charSpacing: 3 }));
s.addText("A From-Scratch IDS with\nSpoof-Resistant Attack Correlation", tb({ x: 0.9, y: 1.95, w: 11.5, h: 1.8, fontFace: HEAD, fontSize: 40, bold: true, color: WHITE, lineSpacingMultiple: 1.0 }));
s.addText("Own packet pipeline · declarative rule engine · live dashboard · ~42,000 lines of Go", tb({ x: 0.9, y: 3.95, w: 11.5, h: 0.4, fontFace: BODY, fontSize: 16, italic: true, color: ICE }));
s.addShape(p.ShapeType.line, { x: 0.95, y: 4.55, w: 3.2, h: 0, line: { color: TEAL, width: 2 } });
s.addText([
  { text: "Group No.: ", options: { color: ICE } }, { text: "______", options: { color: WHITE, bold: true } },
], tb({ x: 0.9, y: 4.8, w: 11.5, h: 0.4, fontFace: BODY, fontSize: 16 }));
s.addText(
  "Aditya Pratap Singh Bhadoria (24114005)    ·    Aditya Ranjan (24114006)    ·    Daddi Om Santosh (24114028)\nDeokar Parth Rajesh (24114032)    ·    Kothawade Manthan (24114050)    ·    Satyam Sharma (24114088)",
  tb({ x: 0.9, y: 5.35, w: 11.5, h: 1.0, fontFace: BODY, fontSize: 14.5, color: ICE, lineSpacingMultiple: 1.3 })
);
s.addNotes("Good [morning/afternoon]. We are Group ____. Our project is a network intrusion detection system we built from scratch in Go — our own packet-capture path, four parsing stages, a rule engine, and a live dashboard, about forty-two thousand lines of code. What makes it different is how it decides WHO is attacking, which I'll come to. I'm [name]; the six of us each owned one stage of the pipeline.");

// ---------- Slide 2: problem / motivation ----------
s = p.addSlide(); s.background = { color: WHITE };
titleBar(s, "Two problems ordinary IDS alerts leave to you", "Motivation");
const probs = [
  ["1", "Alerts, not incidents", "A real attack is a recon scan, an exploit, then a callback — but a signature IDS emits three separate, unlinked alerts. A human or a SIEM has to stitch them back together."],
  ["2", "Forged sources frame victims", "Most engines blame the source IP in the packet. But that address is trivially spoofed in UDP, ICMP and SYN floods — so an attacker can forge a victim's address and make the IDS accuse the victim."],
];
probs.forEach((c, i) => {
  const x = 0.7 + i * 6.15;
  s.addShape(p.ShapeType.roundRect, { x, y: 1.9, w: 5.75, h: 3.9, rectRadius: 0.12, fill: { color: CARD }, line: { color: LINE, width: 1 } });
  chip(s, x + 0.4, 2.3, c[0], TEALD);
  s.addText(c[1], tb({ x: x + 1.1, y: 2.3, w: 4.4, h: 0.6, fontFace: HEAD, fontSize: 21, bold: true, color: NAVY, valign: "middle" }));
  s.addText(c[2], tb({ x: x + 0.4, y: 3.15, w: 5.0, h: 2.4, fontFace: BODY, fontSize: 16.5, color: INK, lineSpacingMultiple: 1.25 }));
});
s.addText("Goal: treat source attribution as a first-class, trust-rated property — and correlate alerts into incidents without ever letting forged traffic frame an innocent host.",
  tb({ x: 0.7, y: 6.1, w: 11.9, h: 0.9, fontFace: BODY, fontSize: 16.5, italic: true, color: TEALD, lineSpacingMultiple: 1.2 }));
s.addNotes("Off-the-shelf rules detect single events well, but they leave you two problems. First, they give you alerts, not incidents — a real attack shows up as a scan, an exploit and a callback as three unrelated lines, and someone has to connect them. Second, and more dangerous: most engines attribute an alert to the source IP in the packet. That address is trivial to forge for UDP, ICMP and spoofed SYN floods — so an attacker can spoof a victim's address into flood traffic and make the IDS blame the victim. Our goal was to make attribution a trust-rated property and to correlate attacks without ever letting a forged packet frame an innocent host.");

// ---------- Slide 3: pipeline ----------
s = p.addSlide(); s.background = { color: WHITE };
titleBar(s, "A six-stage pipeline over one shared packet", "The system");
const stages = [
  ["Capture", "libpcap — live or .pcap; bounded queue"],
  ["Lower parse", "Ethernet, VLAN, IPv4/IPv6, ARP"],
  ["Upper parse", "TCP, UDP, ICMP + checksums"],
  ["Stream reassembly", "TCP on app ports → whole messages"],
  ["App parse", "HTTP, DNS, FTP, TLS / JA3"],
  ["Rule engine", "detect → attribute → correlate"],
];
let y = 1.95;
stages.forEach((st, i) => {
  const dark = i === 5;
  s.addShape(p.ShapeType.roundRect, { x: 0.7, y, w: 7.4, h: 0.72, rectRadius: 0.08, fill: { color: dark ? NAVY : CARD }, line: { color: dark ? NAVY : LINE, width: 1 } });
  s.addText(`${i + 1}`, tb({ x: 0.85, y, w: 0.5, h: 0.72, align: "center", valign: "middle", fontFace: HEAD, fontSize: 20, bold: true, color: dark ? TEAL : TEALD }));
  s.addText(st[0], tb({ x: 1.45, y, w: 2.4, h: 0.72, valign: "middle", fontFace: HEAD, fontSize: 16.5, bold: true, color: dark ? WHITE : NAVY }));
  s.addText(st[1], tb({ x: 3.9, y, w: 4.05, h: 0.72, valign: "middle", fontFace: BODY, fontSize: 13.5, color: dark ? ICE : GRAY }));
  if (i < 5) s.addShape(p.ShapeType.line, { x: 4.4, y: y + 0.72, w: 0, h: 0.13, line: { color: GRAY, width: 1.5, endArrowType: "triangle" } });
  y += 0.85;
});
// right-side note card
s.addShape(p.ShapeType.roundRect, { x: 8.5, y: 1.95, w: 4.1, h: 4.95, rectRadius: 0.12, fill: { color: "0F2A4D" }, line: { type: "none" } });
s.addText("One contract: ParsedPacket", tb({ x: 8.8, y: 2.2, w: 3.5, h: 0.5, fontFace: HEAD, fontSize: 18, bold: true, color: TEAL }));
s.addText([
  { text: "Each field is written by exactly one stage, read only by later ones.\n\n", options: {} },
  { text: "No stage rejects a packet — it records what it could decode.\n\n", options: {} },
  { text: "That documented interface is what let six people build six modules in parallel.", options: {} },
], tb({ x: 8.8, y: 2.75, w: 3.55, h: 4.0, fontFace: BODY, fontSize: 15, color: ICE, lineSpacingMultiple: 1.15 }));
s.addNotes("The system is one pipeline of six stages. Capture pulls frames off the wire or from a pcap into a bounded queue. Four parsing stages decode the frame — link layer, transport, TCP reassembly, then the application protocols including a TLS JA3 fingerprint. Everything lands in a single shared structure, the ParsedPacket, where each field is written by exactly one stage and read only by later ones. That one contract is what let the six of us develop six modules independently. The last stage — the rule engine — is where detection, attribution and correlation happen.");

// ---------- Slide 4: novelty — attribution ----------
s = p.addSlide(); s.background = { color: WHITE };
titleBar(s, "Every alert is tagged reliable or spoofable", "Novelty · 1 of 2");
s.addText("A source IP is evidence only if the sender had to receive a reply to get that far.", tb({ x: 0.7, y: 1.75, w: 11.9, h: 0.5, fontFace: BODY, fontSize: 17, italic: true, color: TEALD }));
// two columns
const col = [
  ["RELIABLE", TEALD, "Needs a completed TCP handshake or a reassembled stream", ["Web attacks — SQLi, XSS, Log4Shell", "DNS-over-TCP tunnelling", "Slowloris · C2 beaconing", "ARP spoofing (keyed on sender MAC)"], "The source had to answer a SYN-ACK or be the real L2 sender — it cannot be a one-packet forgery."],
  ["SPOOFABLE", "B4532A", "One forged packet is enough to trigger it", ["SYN / UDP / ICMP floods", "Port scans · host sweeps", "DNS amplification / reflection", "TTL anomaly · baseline spikes"], "The named source may be a victim, not the attacker — so it can never, alone, accuse anyone."],
];
col.forEach((c, i) => {
  const x = 0.7 + i * 6.15;
  s.addShape(p.ShapeType.roundRect, { x, y: 2.45, w: 5.75, h: 4.45, rectRadius: 0.12, fill: { color: i ? "FBF2EE" : "EAF6F3" }, line: { color: i ? "E3C7BC" : "BfE4DC", width: 1 } });
  s.addText(c[0], tb({ x: x + 0.4, y: 2.7, w: 5, h: 0.5, fontFace: HEAD, fontSize: 20, bold: true, color: c[1] }));
  s.addText(c[2], tb({ x: x + 0.4, y: 3.2, w: 5, h: 0.5, fontFace: BODY, fontSize: 14.5, italic: true, color: INK }));
  s.addText(c[3].map((t, j) => ({ text: t, options: { bullet: { indent: 14 }, breakLine: true, paraSpaceAfter: 5 } })),
    tb({ x: x + 0.5, y: 3.75, w: 4.9, h: 2.0, fontFace: BODY, fontSize: 14.5, color: INK }));
  s.addText(c[4], tb({ x: x + 0.4, y: 5.95, w: 5, h: 0.85, fontFace: BODY, fontSize: 13, color: GRAY, lineSpacingMultiple: 1.1 }));
});
s.addNotes("Here is the core idea. A source IP address is only evidence when the sender had to receive a reply to get that far. So every alert we raise is tagged one of two ways. Reliable, on the left: the detection needed a completed TCP handshake or a reassembled stream — web attacks, DNS tunnelling over TCP, slowloris, beacons, and ARP spoofing which we key on the sender's MAC. The source had to really be there. Spoofable, on the right: a single forged packet is enough — floods, scans, reflection, TTL and baseline anomalies. For those, the named source might be the victim, not the attacker. A table test checks every detector against this classification.");

// ---------- Slide 5: novelty — correlation ----------
s = p.addSlide(); s.background = { color: NAVY };
s.addText("NOVELTY · 2 OF 2", tb({ x: 0.7, y: 0.45, w: 12, h: 0.35, fontFace: BODY, fontSize: 13, bold: true, color: TEAL, charSpacing: 2 }));
s.addText("Correlation that can't be tricked into framing a victim", tb({ x: 0.7, y: 0.74, w: 12, h: 0.8, fontFace: HEAD, fontSize: 28, bold: true, color: WHITE }));
// kill chain flow
const kc = ["Recon\nscan", "Exploit\n(Log4Shell)", "C2\ncallback"];
kc.forEach((t, i) => {
  const x = 0.9 + i * 2.75;
  s.addShape(p.ShapeType.roundRect, { x, y: 2.0, w: 2.3, h: 1.3, rectRadius: 0.1, fill: { color: NAVY2 }, line: { color: TEAL, width: 1.5 } });
  s.addText(t, tb({ x, y: 2.0, w: 2.3, h: 1.3, align: "center", valign: "middle", fontFace: BODY, fontSize: 16, bold: true, color: WHITE, lineSpacingMultiple: 1.0 }));
  if (i < 2) s.addShape(p.ShapeType.line, { x: x + 2.3, y: 2.65, w: 0.45, h: 0, line: { color: TEAL, width: 2.5, endArrowType: "triangle" } });
});
s.addText("→  one CRITICAL incident", tb({ x: 9.0, y: 2.25, w: 3.9, h: 0.9, valign: "middle", fontFace: HEAD, fontSize: 19, bold: true, color: TEAL }));
// framing resistance card
s.addShape(p.ShapeType.roundRect, { x: 0.9, y: 3.9, w: 11.5, h: 2.9, rectRadius: 0.12, fill: { color: "0F2A4D" }, line: { type: "none" } });
s.addText("The rule that makes it safe", tb({ x: 1.25, y: 4.15, w: 10, h: 0.5, fontFace: HEAD, fontSize: 19, bold: true, color: WHITE }));
s.addText([
  { text: "A spoofable alert never names an attacker. ", options: { bold: true, color: TEAL } },
  { text: "A UDP flood forged to look like it comes from host Z adds to Z's ", options: { color: ICE } },
  { text: "victim", options: { italic: true, color: WHITE } },
  { text: " history — but an incident accusing Z as the ", options: { color: ICE } },
  { text: "attacker", options: { italic: true, color: WHITE } },
  { text: " requires Z to have a reliable alert of its own against that victim. So a spoofed source cannot manufacture an intrusion against an innocent host. A dedicated test (", options: { color: ICE } },
  { text: "spoofed_framing", options: { fontFace: "Courier New", color: TEAL } },
  { text: ") asserts exactly this.", options: { color: ICE } },
], tb({ x: 1.25, y: 4.75, w: 10.9, h: 1.9, fontFace: BODY, fontSize: 16.5, lineSpacingMultiple: 1.3 }));
s.addNotes("Correlation builds on that tag. Every alert is added to the history of its source as an attacker and its destination as a victim. An incident rule looks for a kill chain from one source — recon, then exploit, then callback — and fuses it into a single critical incident. Here's the rule that makes it safe: a spoofable alert never names an attacker. A flood forged to look like it came from host Z adds to Z's victim history, but to accuse Z as the attacker the engine demands a reliable alert from Z against that same victim. So a spoofed packet can raise an alert but can never pin a kill chain on an innocent host — and we have a test, spoofed_framing, that asserts exactly that.");

// ---------- Slide 6: coverage ----------
s = p.addSlide(); s.background = { color: WHITE };
titleBar(s, "What it detects — 89 rules, 30 demo captures", "Coverage");
const cats = [
  ["Recon", "vertical & horizontal scans"],
  ["DoS", "SYN/UDP/ICMP flood, LAND, Smurf, Slowloris, RUDY"],
  ["Evasion", "teardrop, ping of death"],
  ["Spoofing", "ARP poisoning, TTL anomaly"],
  ["Web", "SQLi, XSS, traversal, cmd-inj, Log4Shell, Shellshock"],
  ["DNS", "zone transfer, amplification, tunnel, DGA"],
  ["Credential", "FTP brute force"],
  ["Threat intel", "IP / domain / JA3 feeds"],
  ["C2 & anomaly", "periodic beacon, host-fanout baseline"],
];
cats.forEach((c, i) => {
  const cx = 0.7 + (i % 3) * 4.1, cy = 1.95 + Math.floor(i / 3) * 1.55;
  s.addShape(p.ShapeType.roundRect, { x: cx, y: cy, w: 3.85, h: 1.35, rectRadius: 0.1, fill: { color: CARD }, line: { color: LINE, width: 1 } });
  s.addShape(p.ShapeType.ellipse, { x: cx + 0.25, y: cy + 0.25, w: 0.18, h: 0.18, fill: { color: TEAL }, line: { type: "none" } });
  s.addText(c[0], tb({ x: cx + 0.55, y: cy + 0.16, w: 3.1, h: 0.4, fontFace: HEAD, fontSize: 16.5, bold: true, color: NAVY }));
  s.addText(c[1], tb({ x: cx + 0.28, y: cy + 0.62, w: 3.4, h: 0.65, fontFace: BODY, fontSize: 13, color: GRAY, lineSpacingMultiple: 1.1 }));
});
s.addText("…plus two classes of correlated multi-stage incident. Every class has a committed capture that demo/replay.sh re-checks (30/30).",
  tb({ x: 0.7, y: 6.85, w: 11.9, h: 0.5, fontFace: BODY, fontSize: 14, italic: true, color: TEALD }));
s.addNotes("For coverage: the shipped configuration has eighty-nine rules spanning reconnaissance, denial of service, evasion, spoofing, six classes of web exploitation, DNS abuse, credential attacks, threat-intel feed hits, command-and-control beaconing and statistical anomalies — plus two kinds of correlated multi-stage incident. Every one of those classes has a committed packet capture, and a single script replays all thirty and confirms each detector still fires. Right now that's thirty out of thirty.");

// ---------- Slide 7: demo screenshot ----------
s = p.addSlide(); s.background = { color: WHITE };
titleBar(s, "Live dashboard — the kill chain, in real time", "Demo");
const mono = (slide, x, y, w, h, lines, title) => {
  slide.addShape(p.ShapeType.roundRect, { x, y, w, h, rectRadius: 0.06, fill: { color: "0B1B30" }, line: { type: "none" } });
  if (title) slide.addText(title, tb({ x: x + 0.2, y: y + 0.12, w: w - 0.4, h: 0.3, fontFace: BODY, fontSize: 12, bold: true, color: TEAL }));
  slide.addText(lines.join("\n"), tb({ x: x + 0.2, y: y + (title ? 0.5 : 0.2), w: w - 0.4, h: h - (title ? 0.65 : 0.35), fontFace: "Courier New", fontSize: 11, color: "D6E6F5", lineSpacingMultiple: 1.05 }));
};
mono(s, 0.7, 1.9, 7.3, 2.4, [
  "SEV        SCORE KIND         ENTITY                STAGES",
  "[critical]    27 multi_stage  203.0.113.9->10.0.0.80 recon->",
  "                                                 exploit->c2",
  "[critical]    18 compromised  10.0.0.80            exploit->c2",
], "Incidents (2 active)");
mono(s, 0.7, 4.45, 7.3, 2.4, [
  "$ ids query -kind incident",
  "incident high     1001301  203.0.113.9  10.0.0.80",
  "  Multi-stage attack (recon -> exploit -> c2)",
  "",
  "$ ids query -severity critical",
  "alert    critical 1000221  203.0.113.9  10.0.0.80",
  "  Log4Shell JNDI lookup in HTTP header",
], "Query the alert log");
// right column takeaways
const tk = ["One attacker, one incident — built from reliable evidence only", "Credentials (HTTP auth, FTP PASS) are redacted and never logged", "Deterministic: replaying the capture gives the same alerts every time"];
s.addText("What to watch for", tb({ x: 8.5, y: 1.95, w: 4.1, h: 0.5, fontFace: HEAD, fontSize: 18, bold: true, color: NAVY }));
tk.forEach((t, i) => {
  const cy = 2.6 + i * 1.4;
  s.addShape(p.ShapeType.ellipse, { x: 8.5, y: cy, w: 0.32, h: 0.32, fill: { color: TEAL }, line: { type: "none" } });
  s.addText(`${i + 1}`, tb({ x: 8.5, y: cy, w: 0.32, h: 0.32, align: "center", valign: "middle", fontFace: BODY, fontSize: 13, bold: true, color: WHITE }));
  s.addText(t, tb({ x: 8.95, y: cy - 0.05, w: 3.65, h: 1.2, fontFace: BODY, fontSize: 14.5, color: INK, lineSpacingMultiple: 1.15 }));
});
s.addNotes("Now the live demo. On the left is the real dashboard replaying our kill-chain capture: two correlated incidents, built from one attacker. Below it, querying the alert log afterwards — the incident, and the critical Log4Shell alert behind it. Three things to notice. One: it's one attacker, one incident, built only from reliable evidence. Two: credentials — HTTP auth headers and FTP passwords — are redacted at parse time and never written anywhere. Three: because the clock is the packet timestamp, replaying the capture gives identical alerts every single run.");

// ---------- Slide 8: comparison ----------
s = p.addSlide(); s.background = { color: WHITE };
titleBar(s, "How it compares", "Positioning");
const rows = [
  ["Aspect", "This project", "Snort / Suricata", "Zeek"],
  ["Model", "Signature + behavioural + correlation", "Signature (rules)", "Protocol analysis + script"],
  ["Spoof-aware attribution", "Yes — reliable vs spoofable", "No", "Partial (scripting)"],
  ["Spoof-resistant incidents", "Built-in", "Via SIEM", "Via scripts / SIEM"],
  ["Deterministic replay", "Yes — packet-time clock", "No (wall-clock)", "Mostly"],
  ["ReDoS safety", "Yes — RE2, linear time", "No (PCRE)", "n/a"],
  ["Maturity / scale", "Educational, ~42k LOC", "Production, very large", "Production, very large"],
];
const colw = [3.0, 3.6, 3.1, 2.6];
const rowh = [0.6, 0.72, 0.72, 0.68, 0.68, 0.62, 0.68];
let ry = 1.95;
rows.forEach((r, ri) => {
  let rx = 0.7;
  r.forEach((c, ci) => {
    const head = ri === 0;
    const hi = ci === 1 && !head;
    s.addShape(p.ShapeType.rect, { x: rx, y: ry, w: colw[ci], h: rowh[ri], fill: { color: head ? NAVY : (hi ? "EAF6F3" : (ri % 2 ? "F5F8FC" : WHITE)) }, line: { color: LINE, width: 0.75 } });
    s.addText(c, tb({ x: rx + 0.12, y: ry, w: colw[ci] - 0.24, h: rowh[ri], valign: "middle", fontFace: head ? HEAD : BODY, fontSize: head ? 14.5 : 13.5, bold: head || hi || ci === 0, color: head ? WHITE : (hi ? TEALD : INK), lineSpacingMultiple: 1.0 }));
    rx += colw[ci];
  });
  ry += rowh[ri];
});
s.addText("Not a claim of parity in scale — those are large production systems. The point is the design choices the mainstream engines leave to a downstream SIEM.",
  tb({ x: 0.7, y: 6.95, w: 11.9, h: 0.45, fontFace: BODY, fontSize: 13, italic: true, color: GRAY }));
s.addNotes("How does it compare to the systems everyone knows — Snort, Suricata, Zeek? This isn't a claim of parity in scale; those are huge, mature, production tools and ours is an educational build. The point is the design differences. The trust-rated attribution and the built-in, spoof-resistant correlation are things the mainstream engines simply don't do — you'd push their alerts to a SIEM and try to reconstruct it there. We also get deterministic replay from the packet-time clock, and linear-time RE2 matching that can't be driven into a regex denial-of-service.");

// ---------- Slide 9: validation (dark, stat callouts) ----------
s = p.addSlide(); s.background = { color: NAVY };
s.addText("VALIDATION", tb({ x: 0.7, y: 0.45, w: 12, h: 0.35, fontFace: BODY, fontSize: 13, bold: true, color: TEAL, charSpacing: 2 }));
s.addText("Measured, not asserted", tb({ x: 0.7, y: 0.74, w: 12, h: 0.8, fontFace: HEAD, fontSize: 30, bold: true, color: WHITE }));
const stats = [
  ["30/30", "demo captures fire their detector"],
  ["145", "end-to-end scenarios pass"],
  ["0", "false positives on ~24k benign packets"],
  ["~283k", "packets/s replay throughput"],
  ["811 M", "packets in a 60-min soak — 0 drops"],
  ["0 MB", "memory growth under soak (no leak)"],
];
stats.forEach((st, i) => {
  const cx = 0.7 + (i % 3) * 4.1, cy = 2.0 + Math.floor(i / 3) * 2.35;
  s.addShape(p.ShapeType.roundRect, { x: cx, y: cy, w: 3.85, h: 2.05, rectRadius: 0.12, fill: { color: "0F2A4D" }, line: { type: "none" } });
  s.addText(st[0], tb({ x: cx + 0.3, y: cy + 0.28, w: 3.25, h: 0.95, fontFace: HEAD, fontSize: 42, bold: true, color: TEAL }));
  s.addText(st[1], tb({ x: cx + 0.3, y: cy + 1.25, w: 3.3, h: 0.7, fontFace: BODY, fontSize: 14.5, color: ICE, lineSpacingMultiple: 1.1 }));
});
s.addText("All tests run under the Go race detector in CI · every parser is fuzzed (2 defects found & fixed, kept as regression seeds).",
  tb({ x: 0.7, y: 6.95, w: 11.9, h: 0.45, fontFace: BODY, fontSize: 13, italic: true, color: ICE }));
s.addNotes("And does it hold up? Yes — measured, not asserted. All thirty demo captures fire; a hundred and forty-five end-to-end scenarios pass; a benign corpus of twenty-four thousand packets raises zero false positives. On performance, replay runs at about two hundred eighty thousand packets a second, and a sixty-minute soak pushed eight hundred eleven million packets with zero drops and no memory growth — so the bounded tables really do hold flat under load. Everything runs under the race detector in CI, and every parser is fuzzed; fuzzing found two bugs, which we fixed and kept as regression seeds.");

// ---------- Slide 10: conclusion ----------
s = p.addSlide(); s.background = { color: NAVY };
s.addShape(p.ShapeType.ellipse, { x: 10.8, y: 4.6, w: 4.2, h: 4.2, fill: { color: NAVY2 }, line: { type: "none" } });
s.addText("CONCLUSION", tb({ x: 0.9, y: 1.1, w: 12, h: 0.35, fontFace: BODY, fontSize: 13, bold: true, color: TEAL, charSpacing: 2 }));
s.addText("A reproducible IDS that resists both evasion and framing", tb({ x: 0.9, y: 1.5, w: 11.2, h: 1.3, fontFace: HEAD, fontSize: 30, bold: true, color: WHITE, lineSpacingMultiple: 1.0 }));
const concl = [
  "A full capture-to-incident pipeline, built from scratch — ~42k lines of Go, six modules, one shared contract",
  "Its contribution: trust-rated attribution + correlation that provably won't let a spoofed source frame a host",
  "Deterministic (packet-time clock), memory-safe under flood, and ReDoS-free by construction",
  "Future work: a slow second-reference baseline, IP-level reassembly, and SIEM export of incidents",
];
concl.forEach((t, i) => {
  const cy = 3.1 + i * 0.85;
  s.addShape(p.ShapeType.ellipse, { x: 0.95, y: cy + 0.03, w: 0.2, h: 0.2, fill: { color: TEAL }, line: { type: "none" } });
  s.addText(t, tb({ x: 1.35, y: cy - 0.1, w: 10.7, h: 0.8, fontFace: BODY, fontSize: 16.5, color: ICE, lineSpacingMultiple: 1.15 }));
});
s.addText("Thank you — questions welcome.", tb({ x: 0.9, y: 6.75, w: 11, h: 0.5, fontFace: HEAD, fontSize: 18, italic: true, bold: true, color: TEAL }));
s.addNotes("To conclude. We built a complete capture-to-incident IDS from scratch — forty-two thousand lines of Go, six modules against one shared contract. Its real contribution is treating attribution as trust-rated and correlating attacks in a way that provably won't let a spoofed source frame a host. It's deterministic, memory-safe under flood, and free of regex denial-of-service by construction. We're honest about the limits — encrypted DNS is opaque, and an adaptive baseline can be slowly boiled — and the natural next steps are a slow reference baseline, IP-level reassembly, and exporting incidents to a standard SIEM format. Thank you — we're happy to take questions.");

p.writeFile({ fileName: __dirname + "/slides.pptx" }).then((f) => console.log("wrote", f));
