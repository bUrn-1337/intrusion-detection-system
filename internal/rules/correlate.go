package rules

import (
	"container/list"
	"fmt"
	"hash/fnv"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Correlation turns alerts into incidents. It runs in the engine's
// goroutine: every new alert (Kind "alert", not summaries) that emit
// produces is recorded as a contribution in the history of two entities,
// the actor (attacker role) and the target (victim role), and the
// detect:incident rules are evaluated against the histories. Incidents
// are alerts of Kind "incident" (once, when created) and
// "incident_update" (when the stage set grows or the severity rises);
// they bypass dedup and are not fed back into correlation.
//
// Entities are IP addresses, and MAC addresses for arp_spoof alerts (the
// sender MAC is the actor). Each keeps at most corrHistCap contributions
// from the last corrIdle; at most min(MaxKeys, corrMaxEntities) entities
// are kept, least recently active evicted first, and one without a
// contribution for corrIdle is dropped.
//
// Attribution (attribution.go) decides who may be an attacker: a
// contribution from a spoofable alert never makes its actor the attacker
// of an incident on its own. It still counts on the victim's side (its
// score), and it joins a multi_stage chain only once the same actor has
// a reliable alert against the same victim.
//
// The kinds (rule option kind):
//
//   - multi_stage: attacker X and victim Y. The chain events are X's
//     alerts against Y, X's first-stage alerts against any host (the
//     victim set: a sweep before the attack), and, following the victim,
//     Y's own reliable alerts of stages after the from stages, from X's
//     first from-stage alert on Y on. A chain is a time-ordered sequence
//     of events with non-decreasing stages where each event is within
//     first_window (from a first-stage event) or window (from any other)
//     of the previous one. It fires when a chain covers min_stages
//     distinct stages; severity high for 2 stages, critical for 3 or more.
//   - compromised_host: host Y was the victim of a from-stage alert (any
//     attribution) and afterwards, within window, the reliable source of
//     a to-stage alert. Severity critical.
//   - callback: after a reliable from-stage alert X -> Y, Y opens a TCP
//     connection (a new SYN) to X on any port within window. Severity
//     critical.
//
// Score: the number of distinct stages times the sum of the severity
// weights (low 1, medium 2, high 3, critical 4) of the victim's alerts
// in the last 24h (spoofable ones included) plus the chain's other
// alerts (the attacker's against other hosts, the victim's own).

const (
	corrHistCap     = 64
	corrMaxEntities = 10000
	corrIdle        = 24 * time.Hour // entity and contribution expiry
	incidentIdle    = 24 * time.Hour // an incident not updated for this long is forgotten
	maxContributing = 16             // contributing alerts listed in an incident
	// maxIncidentWindow bounds window and first_window: nothing older
	// than corrIdle is kept.
	maxIncidentWindow = int(corrIdle / time.Second)

	defaultMultiStageWindow = time.Hour
	defaultFirstWindow      = 24 * time.Hour
	defaultCompromiseWindow = 24 * time.Hour
	defaultCallbackWindow   = 120 * time.Second
	defaultMinStages        = 2
)

// Alert kinds of incidents.
const (
	KindIncident       = "incident"
	KindIncidentUpdate = "incident_update"
)

// Contribution roles.
const (
	roleAttacker uint8 = iota
	roleVictim
)

// entityKey is an IP address or a MAC address.
type entityKey struct {
	addr  netip.Addr
	mac   mac6
	isMAC bool
}

func addrEntity(a netip.Addr) entityKey { return entityKey{addr: a} }

func (k entityKey) valid() bool { return k.isMAC || k.addr.IsValid() }

func (k entityKey) String() string {
	if k.isMAC {
		return k.mac.String()
	}
	return addrString(k.addr)
}

// contribution is one alert in an entity's history.
type contribution struct {
	t        time.Time
	sid      int
	stage    int // -1: no stage
	weight   int
	role     uint8
	reliable bool
	peer     entityKey // the other entity; zero when the alert has none
}

type entity struct {
	key  entityKey
	last time.Time
	hist []contribution // time order, oldest first
}

type incKey struct {
	sid  int
	a, b entityKey
}

type incident struct {
	key     incKey
	id      string
	stages  stageSet
	sev     string
	created time.Time
	last    time.Time
}

type correlator struct {
	max     int
	ents    map[entityKey]*list.Element // Value is *entity
	entLRU  list.List                   // front = least recently active
	entStat *tableStat
	incs    map[incKey]*list.Element // Value is *incident
	incLRU  list.List
	incStat *tableStat
	stages  []string // the stage names the histories were recorded with
}

func newCorrelator(maxKeys int, entStat, incStat *tableStat) *correlator {
	return &correlator{max: min(maxKeys, corrMaxEntities), ents: make(map[entityKey]*list.Element), entStat: entStat,
		incs: make(map[incKey]*list.Element), incStat: incStat}
}

func (c *correlator) clear() {
	c.entStat.keys.Add(-int64(len(c.ents)))
	c.incStat.keys.Add(-int64(len(c.incs)))
	clear(c.ents)
	clear(c.incs)
	c.entLRU.Init()
	c.incLRU.Init()
}

// use makes rs the rule set: histories recorded with other stage
// directives are dropped, as their stage numbers mean something else.
func (c *correlator) use(rs *RuleSet) {
	if len(rs.incident) == 0 || !slices.Equal(c.stages, rs.stages.names) {
		c.clear()
	}
	c.stages = slices.Clone(rs.stages.names)
}

func (c *correlator) prune(now time.Time) {
	for el := c.entLRU.Front(); el != nil; el = c.entLRU.Front() {
		if now.Sub(el.Value.(*entity).last) <= corrIdle {
			break
		}
		c.removeEntity(el)
	}
	for el := c.incLRU.Front(); el != nil; el = c.incLRU.Front() {
		if now.Sub(el.Value.(*incident).last) <= incidentIdle {
			break
		}
		delete(c.incs, c.incLRU.Remove(el).(*incident).key)
		c.incStat.keys.Add(-1)
	}
}

func (c *correlator) removeEntity(el *list.Element) {
	delete(c.ents, c.entLRU.Remove(el).(*entity).key)
	c.entStat.keys.Add(-1)
}

func (c *correlator) entity(k entityKey) *entity {
	if el, ok := c.ents[k]; ok {
		return el.Value.(*entity)
	}
	return nil
}

// record appends ct to the history of k at ct.t.
func (c *correlator) record(k entityKey, ct contribution) {
	var en *entity
	if el, ok := c.ents[k]; ok {
		en = el.Value.(*entity)
		c.entLRU.MoveToBack(el)
	} else {
		if len(c.ents) >= c.max {
			c.removeEntity(c.entLRU.Front())
			c.entStat.evictions.Add(1)
		}
		en = &entity{key: k}
		c.ents[k] = c.entLRU.PushBack(en)
		c.entStat.keys.Add(1)
	}
	en.last = ct.t
	i := 0
	for i < len(en.hist) && ct.t.Sub(en.hist[i].t) > corrIdle {
		i++
	}
	en.hist = en.hist[i:]
	if len(en.hist) >= corrHistCap {
		en.hist = slices.Delete(en.hist, evictIndex(en.hist), evictIndex(en.hist)+1)
	}
	en.hist = append(en.hist, ct)
}

// evictIndex picks the contribution to drop from a full history: the
// oldest one that a newer one repeats (same stage, role, peer and
// attribution), so a long attack of one kind cannot push out the
// earlier stages; the oldest one if there is none.
func evictIndex(h []contribution) int {
	for i := range h {
		for j := i + 1; j < len(h); j++ {
			if h[j].stage == h[i].stage && h[j].role == h[i].role && h[j].peer == h[i].peer && h[j].reliable == h[i].reliable {
				return i
			}
		}
	}
	return 0
}

// severityWeight is the score weight of a severity.
func severityWeight(s string) int {
	switch s {
	case SeverityLow:
		return 1
	case SeverityMedium:
		return 2
	case SeverityHigh:
		return 3
	case SeverityCritical:
		return 4
	}
	return 0
}

// actorTarget returns the entities an alert of r about v is from and
// against. The target may be invalid (no second entity).
func actorTarget(r *Rule, v *view) (actor, target entityKey) {
	switch r.Detect {
	case DetectARPSpoof:
		// The sender MAC is the identity; the address it claims is the
		// target.
		if v.p != nil {
			if m, ok := toMAC(v.p.ARPSenderMAC); ok {
				return entityKey{mac: m, isMAC: true}, addrEntity(v.src)
			}
		}
	case DetectNXDomainBurst:
		// The view is a response: the client is its destination.
		return addrEntity(v.dst), entityKey{}
	}
	return addrEntity(v.src), addrEntity(v.dst)
}

// alert records a new alert a of rule r about v and evaluates the
// incident rules; it appends any incidents to out.
func (c *correlator) alert(rs *RuleSet, r *Rule, v *view, a *Alert, now time.Time, out []Alert) []Alert {
	c.prune(now)
	actor, target := actorTarget(r, v)
	if !actor.valid() {
		return out
	}
	ct := contribution{t: now, sid: r.SID, stage: r.stage, weight: severityWeight(a.Severity),
		reliable: a.Details[detailAttribution] == attrReliable}
	if target.valid() {
		vt := ct
		vt.role, vt.peer = roleVictim, actor
		c.record(target, vt)
	}
	ct.role, ct.peer = roleAttacker, target
	c.record(actor, ct)
	if ct.stage < 0 {
		return out
	}
	for _, ir := range rs.incident {
		switch ir.incKind {
		case IncidentMultiStage:
			if target.valid() {
				out = c.multiStage(rs, ir, actor, target, now, out)
			}
			if ct.reliable {
				// Follow the victim: actor may be the victim of an
				// earlier from-stage alert.
				for _, x := range c.exploiters(ir, actor, now) {
					if x != target {
						out = c.multiStage(rs, ir, x, actor, now, out)
					}
				}
			}
		case IncidentCompromisedHost:
			if ct.reliable && ir.toStages.has(ct.stage) {
				out = c.compromised(rs, ir, actor, now, out)
			}
		}
	}
	return out
}

// exploiters lists the distinct entities that raised a from-stage alert
// against y, most recent first.
func (c *correlator) exploiters(r *Rule, y entityKey, now time.Time) []entityKey {
	ey := c.entity(y)
	if ey == nil {
		return nil
	}
	var xs []entityKey
	for i := len(ey.hist) - 1; i >= 0; i-- {
		h := &ey.hist[i]
		if h.role == roleVictim && r.fromStages.has(h.stage) && h.peer.valid() && !slices.Contains(xs, h.peer) {
			xs = append(xs, h.peer)
		}
	}
	return xs
}

// chainEvent is one event of a multi_stage chain.
type chainEvent struct {
	contribution
	actor entityKey
}

// multiStage evaluates the pair (attacker x, victim y).
func (c *correlator) multiStage(rs *RuleSet, r *Rule, x, y entityKey, now time.Time, out []Alert) []Alert {
	ex, ey := c.entity(x), c.entity(y)
	if ex == nil || !r.matchAddrs(&view{src: x.addr, dst: y.addr}) {
		return out
	}
	// A spoofable alert never names its source as the attacker: x needs
	// a reliable alert against y.
	corroborated := false
	for i := range ex.hist {
		h := &ex.hist[i]
		if h.role == roleAttacker && h.peer == y && h.reliable {
			corroborated = true
			break
		}
	}
	if !corroborated {
		return out
	}
	var evs []chainEvent
	var fromAt time.Time
	for _, h := range ex.hist {
		if h.role != roleAttacker || h.stage < 0 || h.peer != y && h.stage != 0 {
			continue
		}
		evs = append(evs, chainEvent{h, x})
		if h.peer == y && r.fromStages.has(h.stage) && (fromAt.IsZero() || h.t.Before(fromAt)) {
			fromAt = h.t
		}
	}
	if ey != nil && x != y && !fromAt.IsZero() {
		after := highestStage(r.fromStages)
		for _, h := range ey.hist {
			if h.role == roleAttacker && h.reliable && h.stage > after && !h.t.Before(fromAt) {
				evs = append(evs, chainEvent{h, y})
			}
		}
	}
	chain := longestChain(evs, r.firstWindow, r.incWindow)
	var set stageSet
	for _, ev := range chain {
		set |= 1 << ev.stage
	}
	n := set.count()
	if n < r.minStages {
		return out
	}
	sev := SeverityHigh
	if n >= 3 {
		sev = SeverityCritical
	}
	score := n * c.victimWeight(y, now, func(ev *chainEvent) bool { return ev.actor == x && ev.peer == y }, chain)
	f := finding{kind: r.incKind, key: incKey{sid: r.SID, a: x, b: y}, stages: set, sev: sev, chain: chain, score: score,
		src: x, dst: y, details: map[string]string{
			"attacker": x.String(), "victim": y.String(), "entity": x.String() + " -> " + y.String(),
			"attribution_note": "attacker named only by reliable alerts: a completed handshake, the application layer, the stream layer, a beacon or a MAC; spoofable alerts count only once the attacker has one against the same victim",
		}}
	return c.report(rs, r, &f, now, out)
}

// highestStage returns the highest stage in s, -1 if s is empty.
func highestStage(s stageSet) int {
	h := -1
	for i := range maxStages {
		if s.has(i) {
			h = i
		}
	}
	return h
}

// longestChain returns a chain of events covering the most distinct
// stages (then the most events): time order, non-decreasing stages, each
// event within first (after a stage-0 event) or win (after any other) of
// the previous one.
func longestChain(evs []chainEvent, first, win time.Duration) []chainEvent {
	if len(evs) == 0 {
		return nil
	}
	slices.SortStableFunc(evs, func(a, b chainEvent) int {
		if c := a.t.Compare(b.t); c != 0 {
			return c
		}
		return a.stage - b.stage
	})
	type best struct{ stages, events, prev int }
	bs := make([]best, len(evs))
	top := 0
	for i := range evs {
		bs[i] = best{1, 1, -1}
		for j := range i {
			if evs[j].stage > evs[i].stage {
				continue
			}
			limit := win
			if evs[j].stage == 0 {
				limit = first
			}
			if evs[i].t.Sub(evs[j].t) > limit {
				continue
			}
			s, n := bs[j].stages, bs[j].events+1
			if evs[i].stage > evs[j].stage {
				s++
			}
			if s > bs[i].stages || s == bs[i].stages && n > bs[i].events {
				bs[i] = best{s, n, j}
			}
		}
		if bs[i].stages > bs[top].stages || bs[i].stages == bs[top].stages && bs[i].events >= bs[top].events {
			top = i
		}
	}
	var chain []chainEvent
	for i := top; i >= 0; i = bs[i].prev {
		chain = append(chain, evs[i])
	}
	slices.Reverse(chain)
	return chain
}

// victimWeight sums the severity weights of y's alerts as a victim in the
// last corrIdle, plus those of the chain events that inVictim says are
// not among them.
func (c *correlator) victimWeight(y entityKey, now time.Time, inVictim func(*chainEvent) bool, chain []chainEvent) int {
	w := 0
	if ey := c.entity(y); ey != nil {
		for _, h := range ey.hist {
			if h.role == roleVictim && now.Sub(h.t) <= corrIdle {
				w += h.weight
			}
		}
	}
	for i := range chain {
		if !inVictim(&chain[i]) {
			w += chain[i].weight
		}
	}
	return w
}

// compromised evaluates host y for compromised_host.
func (c *correlator) compromised(rs *RuleSet, r *Rule, y entityKey, now time.Time, out []Alert) []Alert {
	ey := c.entity(y)
	if ey == nil {
		return out
	}
	var (
		chain   []chainEvent
		set     stageSet
		exploit *contribution
		used    = make([]bool, len(ey.hist))
	)
	for i := range ey.hist {
		h := &ey.hist[i]
		if h.role != roleAttacker || !h.reliable || !r.toStages.has(h.stage) {
			continue
		}
		var e *contribution
		for j := range ey.hist {
			x := &ey.hist[j]
			if x.role == roleVictim && r.fromStages.has(x.stage) && !x.t.After(h.t) && h.t.Sub(x.t) <= r.incWindow {
				if !used[j] {
					used[j] = true
					chain = append(chain, chainEvent{*x, x.peer})
					set |= 1 << x.stage
				}
				e = x
			}
		}
		if e == nil {
			continue
		}
		exploit = e
		chain = append(chain, chainEvent{*h, y})
		set |= 1 << h.stage
	}
	if exploit == nil || !r.matchAddrs(&view{src: y.addr, dst: exploit.peer.addr}) {
		return out
	}
	slices.SortStableFunc(chain, func(a, b chainEvent) int { return a.t.Compare(b.t) })
	score := set.count() * c.victimWeight(y, now, func(ev *chainEvent) bool { return ev.actor != y }, chain)
	attr := attrSpoofable
	if exploit.reliable {
		attr = attrReliable
	}
	f := finding{kind: r.incKind, key: incKey{sid: r.SID, a: y}, stages: set, sev: SeverityCritical, chain: chain, score: score,
		src: y, dst: exploit.peer, details: map[string]string{
			"host": y.String(), "entity": y.String(), "exploited_by": exploit.peer.String(), "exploited_by_attribution": attr,
			"attribution_note": "the host is the reliable source of the later alerts; exploited_by comes from an alert of any attribution and is not named as an attacker",
		}}
	return c.report(rs, r, &f, now, out)
}

// connStart handles a new TCP connection attempt (a SYN that opened a
// handshake) from y to x, for the callback rules.
func (c *correlator) connStart(rs *RuleSet, y, x netip.Addr, yport, xport uint16, now time.Time, out []Alert) []Alert {
	c.prune(now)
	ey := c.entity(addrEntity(y))
	if ey == nil {
		return out
	}
	for _, r := range rs.incident {
		if r.incKind != IncidentCallback || !r.matchAddrs(&view{src: x, dst: y}) {
			continue
		}
		// The latest reliable from-stage alert x -> y within window.
		var ex *contribution
		for i := len(ey.hist) - 1; i >= 0; i-- {
			h := &ey.hist[i]
			if h.role == roleVictim && h.reliable && r.fromStages.has(h.stage) && h.peer == addrEntity(x) &&
				!h.t.After(now) && now.Sub(h.t) <= r.incWindow {
				ex = h
				break
			}
		}
		if ex == nil {
			continue
		}
		xk, yk := addrEntity(x), addrEntity(y)
		chain := []chainEvent{{*ex, xk}}
		set := stageSet(1 << ex.stage)
		// The callback counts as one more stage in the score.
		score := (set.count() + 1) * c.victimWeight(yk, now, func(*chainEvent) bool { return true }, chain)
		f := finding{kind: r.incKind, key: incKey{sid: r.SID, a: xk, b: yk}, stages: set, sev: SeverityCritical, chain: chain, score: score,
			src: yk, dst: xk, sport: yport, dport: xport, extraStage: "callback", details: map[string]string{
				"attacker": xk.String(), "victim": yk.String(), "entity": yk.String() + " -> " + xk.String(),
				"callback":         netip.AddrPortFrom(y, yport).String() + " -> " + netip.AddrPortFrom(x, xport).String(),
				"exploit_sid":      strconv.Itoa(ex.sid),
				"delay":            now.Sub(ex.t).Round(time.Millisecond).String(),
				"attribution_note": "attacker named by a reliable exploit alert; the callback SYN comes from the victim",
			}}
		out = c.report(rs, r, &f, now, out)
	}
	return out
}

// finding is one evaluation that met an incident rule.
type finding struct {
	kind         string
	key          incKey
	stages       stageSet
	sev          string
	chain        []chainEvent
	score        int
	src, dst     entityKey
	sport, dport uint16
	extraStage   string // appended to the chain text (callback)
	details      map[string]string
}

func severityRank(s string) int { return severityWeight(s) }

// report creates or updates the incident of f and emits it when it is
// new, its stage set grew or its severity rose.
func (c *correlator) report(rs *RuleSet, r *Rule, f *finding, now time.Time, out []Alert) []Alert {
	kind := KindIncidentUpdate
	var inc *incident
	if el, ok := c.incs[f.key]; ok {
		inc = el.Value.(*incident)
		c.incLRU.MoveToBack(el)
		inc.last = now
		grown := f.stages|inc.stages != inc.stages
		rose := severityRank(f.sev) > severityRank(inc.sev)
		if !grown && !rose {
			return out
		}
		inc.stages |= f.stages
		if rose {
			inc.sev = f.sev
		}
	} else {
		kind = KindIncident
		if len(c.incs) >= c.max {
			old := c.incLRU.Front()
			delete(c.incs, c.incLRU.Remove(old).(*incident).key)
			c.incStat.keys.Add(-1)
			c.incStat.evictions.Add(1)
		}
		inc = &incident{key: f.key, id: incidentID(f.kind, f.key), stages: f.stages, sev: f.sev, created: now, last: now}
		c.incs[f.key] = c.incLRU.PushBack(inc)
		c.incStat.keys.Add(1)
	}
	names := rs.stages.setNames(inc.stages)
	chainText := strings.Join(names, " -> ")
	if f.extraStage != "" {
		chainText += " -> " + f.extraStage
	}
	contrib := make([]string, 0, min(len(f.chain), maxContributing))
	for i, ev := range f.chain {
		if i == maxContributing {
			break
		}
		contrib = append(contrib, strconv.Itoa(ev.sid)+"@"+ev.t.UTC().Format(time.RFC3339Nano))
	}
	d := f.details
	d["detector"] = DetectIncident
	d["kind"] = f.kind
	d["incident_id"] = inc.id
	d["stages"] = strings.Join(names, ",")
	d["chain"] = chainText
	d["contributing"] = strings.Join(contrib, ",")
	d["contributing_total"] = strconv.Itoa(len(f.chain))
	d["score"] = strconv.Itoa(f.score)
	d[detailAttribution] = attrReliable
	out = append(out, Alert{
		Time: now, FirstSeen: inc.created, LastSeen: now,
		SID: r.SID, Rev: r.Rev, Msg: r.Msg, Severity: inc.sev, Category: r.Category,
		Proto: groupNames[gIP], SrcIP: f.src.String(), DstIP: f.dst.String(), SrcPort: f.sport, DstPort: f.dport,
		Count: 1, Kind: kind, Details: d,
	})
	return out
}

// incidentID is a stable id for an incident: the same kind, rule and
// entities always give the same id.
func incidentID(kind string, k incKey) string {
	h := fnv.New64a()
	fmt.Fprintf(h, "%s|%d|%s|%s", kind, k.sid, k.a, k.b)
	return fmt.Sprintf("inc-%016x", h.Sum64())
}

// parseIncident checks and completes a detect:incident rule.
func parseIncident(r *Rule, kind string, seen map[string]bool, st *stageTable, fail func(string, ...any)) {
	if seen["severity"] {
		fail("severity is not valid with detect:incident (an incident's severity is computed)")
	}
	switch kind {
	case IncidentMultiStage, IncidentCompromisedHost, IncidentCallback:
	default:
		fail("kind %q: want multi_stage, compromised_host or callback", kind)
		return
	}
	r.incKind = kind
	if len(st.names) == 0 {
		fail("detect:incident needs stage directives (stage NAME CATEGORY[,CATEGORY...])")
		return
	}
	if kind != IncidentMultiStage && (seen["min_stages"] || seen["first_window"]) {
		fail("min_stages and first_window are only valid with kind:multi_stage")
	}
	if kind != IncidentCompromisedHost && seen["to"] {
		fail("to is only valid with kind:compromised_host")
	}
	defaultSet := func(opt string, names ...string) stageSet {
		var s stageSet
		for _, n := range names {
			i := st.index(n)
			if i < 0 {
				fail("%s: the default stage %s is not defined; give %s:STAGE[,STAGE...]", opt, n, opt)
				return 0
			}
			s |= 1 << i
		}
		return s
	}
	if !seen["from"] && (kind != IncidentMultiStage || st.index("exploit") >= 0) {
		// multi_stage only uses from to follow the victim, so a file
		// without an exploit stage just does not.
		r.fromStages = defaultSet("from", "exploit")
	}
	switch kind {
	case IncidentMultiStage:
		if !seen["min_stages"] {
			r.minStages = defaultMinStages
		}
		if r.minStages > len(st.names) {
			fail("min_stages %d: the file defines only %d stages", r.minStages, len(st.names))
		}
		if !seen["window"] {
			r.incWindow = defaultMultiStageWindow
		}
		if !seen["first_window"] {
			r.firstWindow = defaultFirstWindow
		}
	case IncidentCompromisedHost:
		if !seen["to"] {
			r.toStages = defaultSet("to", "c2", "exfil")
		}
		if !seen["window"] {
			r.incWindow = defaultCompromiseWindow
		}
		if r.fromStages&r.toStages != 0 {
			fail("from and to share a stage")
		}
	case IncidentCallback:
		if !seen["window"] {
			r.incWindow = defaultCallbackWindow
		}
	}
}
