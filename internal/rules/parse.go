package rules

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/bUrn-1337/intrusion-detection-system/internal/packet"
)

// Limits on numeric option values. count bounds the per-key deque, so it
// also bounds memory.
const (
	maxCount = 100000
	// maxByteCount bounds count for udp_flood metric:bytes, which sums
	// bytes in fixed memory instead of storing events.
	maxByteCount = 1 << 40
	maxSeconds   = 86400
	maxLineLen   = 1 << 20
	// maxDistinct bounds distinct_ports, distinct_hosts and
	// max_distinct_ports: a distinctCounter key holds that many values
	// plus one and searches them linearly.
	maxDistinct = 1000

	defaultMaxDistinctPorts = 5
	defaultMinSamples       = 10
	defaultMaxHopDiff       = 3
	defaultMinFragSize      = 256
	// defaultMaxReplyRatio is udp_flood's max_reply_ratio: at most 1
	// reply per 50 packets. A QUIC download acknowledges about every
	// tenth to twentieth packet and a call talks back about as much as
	// it receives, both far above it; a flood gets no UDP back at all.
	defaultMaxReplyRatio = 0.02
)

// SyntaxError is one problem in a rule file.
type SyntaxError struct {
	File   string
	Line   int
	Reason string
}

func (e *SyntaxError) Error() string {
	return fmt.Sprintf("%s:%d: %s", e.File, e.Line, e.Reason)
}

// LoadError holds every SyntaxError found in a rule file, in line order.
type LoadError struct {
	Errors []*SyntaxError
}

func (e *LoadError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d error(s) in rule file:", len(e.Errors))
	for _, se := range e.Errors {
		b.WriteString("\n  " + se.Error())
	}
	return b.String()
}

// Unwrap returns the individual errors, for errors.As and errors.Is.
func (e *LoadError) Unwrap() []error {
	out := make([]error, len(e.Errors))
	for i, se := range e.Errors {
		out[i] = se
	}
	return out
}

// Load reads and parses a rule file. On any syntax error it returns a nil
// RuleSet and a *LoadError listing every problem in the file; an I/O
// error is returned as is.
func Load(path string) (*RuleSet, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Parse(f, path)
}

// Parse parses rules from r. name is used as the file name in errors.
func Parse(r io.Reader, name string) (*RuleSet, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), maxLineLen)

	var (
		lines  []srcLine
		errs   []lineError
		lineNo int
	)
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		lines = append(lines, srcLine{lineNo, line})
	}
	if err := sc.Err(); err != nil {
		if !errors.Is(err, bufio.ErrTooLong) {
			return nil, err
		}
		errs = append(errs, lineError{lineNo + 1, fmt.Sprintf("line longer than %d bytes", maxLineLen)})
	}

	// Variables first: a rule may use one defined further down.
	vars, verrs := parseVars(lines)
	errs = append(errs, verrs...)
	static, aerrs := parseARPBinds(lines)
	errs = append(errs, aerrs...)

	var (
		rules   []*Rule
		sidLine = make(map[int]int)
	)
	for _, l := range lines {
		if isVarLine(l.text) || isARPBindLine(l.text) {
			continue
		}
		rule, reasons := parseRule(l.text, vars)
		if rule != nil {
			if first, dup := sidLine[rule.SID]; dup {
				reasons = append(reasons, fmt.Sprintf("duplicate sid %d (first defined on line %d)", rule.SID, first))
			} else {
				sidLine[rule.SID] = l.n
			}
		}
		for _, reason := range reasons {
			errs = append(errs, lineError{l.n, reason})
		}
		if rule != nil && len(reasons) == 0 {
			rule.File, rule.Line = name, l.n
			rules = append(rules, rule)
		}
	}
	if len(errs) > 0 {
		slices.SortStableFunc(errs, func(a, b lineError) int { return a.line - b.line })
		le := &LoadError{}
		for _, e := range errs {
			le.Errors = append(le.Errors, &SyntaxError{File: name, Line: e.line, Reason: e.reason})
		}
		return nil, le
	}
	return newRuleSet(name, rules, static), nil
}

func isARPBindLine(line string) bool {
	f := strings.Fields(line)
	return len(f) > 0 && f[0] == "arpbind"
}

// parseARPBinds reads every "arpbind IP MAC" line: a static IPv4 -> MAC
// binding for detect:arp_spoof kind:static_violation.
func parseARPBinds(lines []srcLine) (map[netip.Addr]mac6, []lineError) {
	var (
		static map[netip.Addr]mac6
		first  = make(map[netip.Addr]int)
		errs   []lineError
	)
	for _, l := range lines {
		if !isARPBindLine(l.text) {
			continue
		}
		fail := func(format string, args ...any) {
			errs = append(errs, lineError{l.n, fmt.Sprintf(format, args...)})
		}
		f := strings.Fields(l.text)
		if len(f) != 3 {
			fail("arpbind: want arpbind IPV4_ADDRESS MAC_ADDRESS")
			continue
		}
		ip, err := netip.ParseAddr(f[1])
		if err != nil || !ip.Is4() || ip.IsUnspecified() {
			fail("arpbind address %q: want an IPv4 address other than 0.0.0.0", f[1])
			continue
		}
		hw, err := net.ParseMAC(f[2])
		m, ok := toMAC(hw)
		if err != nil || !ok {
			fail("arpbind MAC %q: want six hex octets, e.g. 00:11:22:33:44:55", f[2])
			continue
		}
		if reason := invalidMACReason(m); reason != "" {
			fail("arpbind MAC %s is %s, not a host address", m, reason)
			continue
		}
		if n, dup := first[ip]; dup {
			fail("arpbind %s given twice (first defined on line %d)", ip, n)
			continue
		}
		first[ip] = l.n
		if static == nil {
			static = make(map[netip.Addr]mac6)
		}
		static[ip] = m
	}
	return static, errs
}

// srcLine is one non-blank, non-comment line of a rule file.
type srcLine struct {
	n    int
	text string
}

// lineError is one problem, before it is given the file name.
type lineError struct {
	line   int
	reason string
}

// parseRule parses one non-comment line. It returns every problem found.
// The rule is nil only when the SID could not be determined, so duplicate
// SIDs are still detected on lines with other errors.
func parseRule(line string, vars varTable) (*Rule, []string) {
	var errs []string
	fail := func(format string, args ...any) { errs = append(errs, fmt.Sprintf(format, args...)) }

	open := strings.IndexByte(line, '(')
	if open < 0 {
		return nil, []string{"missing options: expected \"(msg:...; sid:...;)\" after the header"}
	}
	if !strings.HasSuffix(line, ")") {
		return nil, []string{"options must end with ')' at the end of the line"}
	}
	header, err := splitHeader(line[:open])
	if err != nil {
		return nil, []string{err.Error()}
	}
	if len(header) != 7 {
		return nil, []string{fmt.Sprintf("header has %d fields, want 7: action proto src_addr src_port direction dst_addr dst_port", len(header))}
	}
	// Expand variables in the address and port fields. A field that fails
	// is left as is, so it is not reported again below.
	for i, what := range []string{2: "source address", 3: "source port", 5: "destination address", 6: "destination port"} {
		if what == "" {
			continue
		}
		kind := "address"
		if i == 3 || i == 6 {
			kind = "port"
		}
		f, err := vars.expand(header[i], kind, nil)
		if err != nil {
			fail("%s: %v", what, err)
			header[i] = "any"
			continue
		}
		header[i] = f
	}

	// text identifies the rule across reloads, so it holds the expanded
	// header: changing a variable changes every rule that uses it.
	r := &Rule{Rev: 1, Severity: SeverityMedium, text: strings.Join(header, " ") + " " + strings.Join(strings.Fields(line[open:]), " ")}
	switch header[0] {
	case "alert":
		r.Action = ActionAlert
	case "pass":
		r.Action = ActionPass
	default:
		fail("unknown action %q (want alert or pass)", header[0])
	}
	protoOK := true
	switch header[1] {
	case "ip":
		r.Proto = ProtoIP
	case "tcp":
		r.Proto = ProtoTCP
	case "udp":
		r.Proto = ProtoUDP
	case "icmp":
		r.Proto = ProtoICMP
	case "arp":
		r.Proto = ProtoARP
	default:
		protoOK = false
		fail("unknown protocol %q (want ip, tcp, udp, icmp or arp)", header[1])
	}
	if r.src, err = parseAddrSpec(header[2]); err != nil {
		fail("source address: %v", err)
	}
	if r.sport, err = parsePortSpec(header[3]); err != nil {
		fail("source port: %v", err)
	}
	switch header[4] {
	case "->":
	case "<>":
		r.bidir = true
	default:
		fail("unknown direction %q (want -> or <>)", header[4])
	}
	if r.dst, err = parseAddrSpec(header[5]); err != nil {
		fail("destination address: %v", err)
	}
	if r.dport, err = parsePortSpec(header[6]); err != nil {
		fail("destination port: %v", err)
	}
	hasPorts := r.Proto == ProtoTCP || r.Proto == ProtoUDP
	if protoOK && !hasPorts && (!r.sport.any || !r.dport.any) {
		fail("ports must be any for protocol %s", r.Proto)
	}

	opts, err := splitOptions(line[open+1 : len(line)-1])
	if err != nil {
		fail("%v", err)
	}
	sidSet := parseOptions(r, opts, vars, fail)

	if r.Msg == "" && !seenOption(opts, "msg") {
		fail("missing required option msg")
	}
	if !sidSet && !seenOption(opts, "sid") {
		fail("missing required option sid")
	}
	if !sidSet {
		return nil, errs
	}
	if protoOK {
		checkProtoOptions(r, fail)
	}
	return r, errs
}

func seenOption(opts []option, key string) bool {
	for _, o := range opts {
		if o.key == key {
			return true
		}
	}
	return false
}

type option struct {
	key, value string
	hasValue   bool
}

// splitHeader splits the header on whitespace, keeping [...] lists
// together (spaces inside a list are dropped).
func splitHeader(s string) ([]string, error) {
	var (
		out   []string
		cur   strings.Builder
		depth int
	)
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '[':
			depth++
			cur.WriteByte(c)
		case c == ']':
			depth--
			if depth < 0 {
				return nil, errors.New("unbalanced ']' in header")
			}
			cur.WriteByte(c)
		case c == ' ' || c == '\t':
			if depth == 0 {
				flush()
			}
		default:
			cur.WriteByte(c)
		}
	}
	if depth != 0 {
		return nil, errors.New("unbalanced '[' in header")
	}
	flush()
	return out, nil
}

// splitOptions splits "k:v; k:v; ..." on semicolons outside double
// quotes. Inside quotes a backslash escapes the next character. The last
// option may omit its semicolon.
func splitOptions(s string) ([]option, error) {
	var (
		parts []string
		start int
		inQ   bool
	)
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case inQ && c == '\\':
			i++
		case c == '"':
			inQ = !inQ
		case !inQ && c == ';':
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	if inQ {
		return nil, errors.New("unterminated quoted string in options")
	}
	if tail := strings.TrimSpace(s[start:]); tail != "" {
		parts = append(parts, tail)
	}
	var opts []option
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			return nil, errors.New("empty option (two ';' in a row?)")
		}
		k, v, ok := strings.Cut(p, ":")
		opts = append(opts, option{key: strings.TrimSpace(k), value: strings.TrimSpace(v), hasValue: ok})
	}
	return opts, nil
}

// parseOptions applies opts to r and reports whether sid was set.
func parseOptions(r *Rule, opts []option, vars varTable, fail func(string, ...any)) bool {
	var (
		sidSet     bool
		seen       = make(map[string]bool)
		lastContnt = -1 // index into r.contents that nocase applies to
		nocaseDone = make(map[int]bool)
		detectOpts []string
		kind       string
		countText  string // the count value, for the error when count > maxCount
	)
	once := map[string]bool{
		"msg": true, "sid": true, "rev": true, "severity": true, "category": true,
		"flags": true, "app_proto": true, "detection_filter": true, "detect": true,
		"track": true, "count": true, "seconds": true, "min_incomplete_ratio": true,
		"max_distinct_ports": true, "distinct_ports": true, "distinct_hosts": true,
		"same_ip": true, "same_port": true, "eth_dst": true, "itype": true, "icode": true,
		"ttl": true, "kind": true, "scope": true, "min_samples": true, "max_hop_diff": true,
		"min_size": true, "arp_op": true, "dsize": true, "metric": true, "max_reply_ratio": true,
	}
	var ratio bool
	for _, o := range opts {
		if once[o.key] {
			if seen[o.key] {
				fail("option %s given more than once", o.key)
				continue
			}
			seen[o.key] = true
		}
		if noValue[o.key] {
			if o.hasValue {
				fail("%s takes no value", o.key)
				continue
			}
		} else if !o.hasValue {
			if knownOption(o.key) {
				fail("option %s needs a value (%s:...)", o.key, o.key)
			} else {
				fail("unknown option %q", o.key)
			}
			continue
		}
		v := o.value
		switch o.key {
		case "msg":
			s, err := unquote(v)
			switch {
			case err != nil:
				fail("msg: %v", err)
			case s == "":
				fail("msg must not be empty")
			default:
				r.Msg = s
			}
		case "sid":
			n, err := parsePositive(v, math.MaxInt32)
			if err != nil {
				fail("sid: %v", err)
				continue
			}
			r.SID, sidSet = n, true
		case "rev":
			n, err := parsePositive(v, math.MaxInt32)
			if err != nil {
				fail("rev: %v", err)
				continue
			}
			r.Rev = n
		case "severity":
			switch v {
			case SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
				r.Severity = v
			default:
				fail("severity %q: want low, medium, high or critical", v)
			}
		case "category":
			if !isName(v) {
				fail("category %q: want letters, digits, '_' or '-'", v)
				continue
			}
			r.Category = v
		case "flags":
			if err := parseFlags(r, v); err != nil {
				fail("flags: %v", err)
			}
		case "content":
			pat, err := parseContent(v)
			if err != nil {
				fail("content: %v", err)
				lastContnt = -2 // a following nocase is not reported again
				continue
			}
			r.contents = append(r.contents, contentMatch{pat: pat})
			lastContnt = len(r.contents) - 1
		case "nocase":
			switch {
			case lastContnt == -1:
				fail("nocase must follow a content option")
			case lastContnt >= 0 && nocaseDone[lastContnt]:
				fail("nocase given twice for the same content")
			case lastContnt >= 0:
				nocaseDone[lastContnt] = true
				c := &r.contents[lastContnt]
				c.nocase, c.pat = true, asciiLower(c.pat)
			}
		case "app_proto":
			switch v {
			case "dns":
				r.appProto = packet.AppDNS
			case "http":
				r.appProto = packet.AppHTTP
			case "ftp":
				r.appProto = packet.AppFTP
			case "tls":
				r.appProto = packet.AppTLS
			default:
				fail("app_proto %q: want dns, http, ftp or tls", v)
			}
		case "app_field":
			k, val, ok := strings.Cut(v, "=")
			k, val = strings.TrimSpace(k), strings.TrimSpace(val)
			if strings.HasPrefix(val, `"`) {
				s, err := unquote(val)
				if err != nil {
					fail("app_field: %v", err)
					continue
				}
				val = s
			}
			switch {
			case !ok:
				fail("app_field %q: want KEY=VALUE", v)
			case !isName(k):
				fail("app_field key %q: want letters, digits, '_' or '-'", k)
			default:
				r.appFields = append(r.appFields, appField{key: k, value: val})
			}
		case "app_reason":
			switch v {
			case packet.ReasonMalformed, packet.ReasonSuspicious:
				r.appReasons = append(r.appReasons, v+"_reason")
			default:
				fail("app_reason %q: want malformed or suspicious", v)
			}
		case "detection_filter":
			ws, err := parseDetectionFilter(v)
			if err != nil {
				fail("detection_filter: %v", err)
				continue
			}
			r.filter = &ws
		case "detect":
			if _, ok := detectorOptions[v]; !ok {
				fail("detect %q: want syn_flood, port_scan, host_sweep, ping_sweep, ttl_anomaly, frag_attack, arp_spoof, udp_flood, icmp_flood or icmp_tunnel", v)
				continue
			}
			r.Detect = v
		case "track":
			detectOpts = append(detectOpts, o.key)
			switch v {
			case "by_src":
				r.detect.track = TrackBySrc
			case "by_dst":
				r.detect.track = TrackByDst
			default:
				fail("track %q: want by_src or by_dst", v)
				continue
			}
		case "count":
			detectOpts = append(detectOpts, o.key)
			// Only udp_flood metric:bytes allows more than maxCount; that is
			// checked after the loop.
			n, err := parsePositive(v, maxByteCount)
			if err != nil {
				_, err = parsePositive(v, maxCount)
				fail("count: %v", err)
				continue
			}
			r.detect.count, countText = n, v
		case "seconds":
			detectOpts = append(detectOpts, o.key)
			n, err := parsePositive(v, maxSeconds)
			if err != nil {
				fail("seconds: %v", err)
				continue
			}
			r.detect.seconds = n
		case "min_incomplete_ratio":
			detectOpts = append(detectOpts, o.key)
			f, err := strconv.ParseFloat(v, 64)
			if err != nil || !(f >= 0 && f <= 1) {
				fail("min_incomplete_ratio %q: want a number from 0 to 1", v)
				continue
			}
			r.minRatio, ratio = f, true
		case "max_distinct_ports":
			detectOpts = append(detectOpts, o.key)
			n, err := parsePositive(v, maxDistinct)
			if err != nil {
				fail("max_distinct_ports: %v", err)
				continue
			}
			r.maxPorts = n
		case "distinct_ports", "distinct_hosts":
			detectOpts = append(detectOpts, o.key)
			if seen["distinct_ports"] && seen["distinct_hosts"] {
				fail("distinct_ports and distinct_hosts cannot both be given")
				continue
			}
			n, err := parsePositive(v, maxDistinct)
			if err != nil {
				fail("%s: %v", o.key, err)
				continue
			}
			r.distinct = n
		case "same_ip":
			r.sameIP = true
		case "same_port":
			r.samePort = true
		case "eth_dst":
			kind, neg := strings.CutPrefix(v, "!")
			switch kind {
			case "broadcast":
				r.ethDst = ethBroadcast
			case "multicast":
				r.ethDst = ethMulticast
			case "zero":
				r.ethDst = ethZero
			default:
				fail("eth_dst %q: want broadcast, multicast or zero, optionally negated with '!'", v)
				continue
			}
			r.ethDstNeg = neg
		case "itype", "icode":
			n, err := strconv.ParseUint(v, 10, 8)
			if err != nil {
				fail("%s %q: want an integer from 0 to 255", o.key, v)
				continue
			}
			if o.key == "itype" {
				r.hasIType, r.itype = true, uint8(n)
			} else {
				r.hasICode, r.icode = true, uint8(n)
			}
		case "ttl":
			c, err := parseTTL(v)
			if err != nil {
				fail("ttl: %v", err)
				continue
			}
			r.ttl = c
		case "dsize":
			c, err := parseDsize(v)
			if err != nil {
				fail("dsize: %v", err)
				continue
			}
			r.dsize = c
		case "kind":
			// Checked below, once the detector is known.
			detectOpts = append(detectOpts, o.key)
			kind = v
		case "arp_op":
			switch v {
			case "request":
				r.arpOp = packet.ARPRequest
			case "reply":
				r.arpOp = packet.ARPReply
			default:
				fail("arp_op %q: want request or reply", v)
			}
		case "scope":
			detectOpts = append(detectOpts, o.key)
			switch v {
			case "external":
				r.external = true
			case "all":
			default:
				fail("scope %q: want external or all", v)
			}
		case "min_samples":
			detectOpts = append(detectOpts, o.key)
			n, err := parsePositive(v, maxCount)
			if err != nil {
				fail("min_samples: %v", err)
				continue
			}
			r.minSamples = n
		case "max_hop_diff":
			detectOpts = append(detectOpts, o.key)
			n, err := strconv.ParseUint(v, 10, 8)
			if err != nil {
				fail("max_hop_diff %q: want an integer from 0 to 255", v)
				continue
			}
			r.maxHopDiff = int(n)
		case "metric":
			detectOpts = append(detectOpts, o.key)
			if v != MetricPackets && v != MetricBytes {
				fail("metric %q: want packets or bytes", v)
				continue
			}
			r.metric = v
		case "max_reply_ratio":
			detectOpts = append(detectOpts, o.key)
			f, err := strconv.ParseFloat(v, 64)
			if err != nil || !(f >= 0 && f <= 1) {
				fail("max_reply_ratio %q: want a number from 0 to 1", v)
				continue
			}
			r.maxReplyRatio = f
		case "min_size":
			detectOpts = append(detectOpts, o.key)
			n, err := parsePositive(v, 65535)
			if err != nil {
				fail("min_size: %v", err)
				continue
			}
			r.minSize = n
		default:
			fail("unknown option %q", o.key)
		}
	}

	if r.Detect == "" {
		if len(detectOpts) > 0 {
			fail("option %s is only valid with detect:%s", detectOpts[0], detectorsTaking(detectOpts[0]))
		}
		return sidSet
	}
	// Detector rule.
	if r.detect.count > maxCount && (r.Detect != DetectUDPFlood || r.metric != MetricBytes) {
		_, err := parsePositive(countText, maxCount)
		fail("count: %v (larger counts need detect:udp_flood metric:bytes)", err)
	}
	spec := detectorOptions[r.Detect]
	var missing []string
	for _, k := range spec.required {
		if !seen[k] {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		fail("detect:%s needs %s", r.Detect, strings.Join(missing, ", "))
	}
	for _, k := range detectOpts {
		if !slices.Contains(spec.required, k) && !slices.Contains(spec.optional, k) {
			fail("option %s is not valid with detect:%s", k, r.Detect)
			break
		}
	}
	switch r.Detect {
	case DetectSYNFlood:
		if !ratio {
			r.minRatio = 0.8
		}
		if r.maxPorts == 0 {
			r.maxPorts = defaultMaxDistinctPorts
		}
	case DetectTTLAnomaly:
		if !seen["scope"] {
			r.external = true
		}
		if !seen["min_samples"] {
			r.minSamples = defaultMinSamples
		}
		if !seen["max_hop_diff"] {
			r.maxHopDiff = defaultMaxHopDiff
		}
		if r.external {
			home, ok := vars["HOME_NET"]
			switch {
			case !ok:
				fail("scope:external needs a HOME_NET variable (var HOME_NET ...), or use scope:all")
			case !home.bad && !home.addr:
				fail("scope:external: $HOME_NET holds ports, not addresses")
			case !home.bad:
				r.homeNet, _ = parseAddrSpec(home.value)
			}
		}
	case DetectFragAttack:
		switch kind {
		case "":
		case FragOverlap, FragTiny, FragOversize, FragFlood:
			r.fragKind = kind
		default:
			fail("kind %q: want overlap, tiny, oversize or flood", kind)
		}
		flood := r.fragKind == FragFlood
		if flood && (!seen["count"] || !seen["seconds"]) {
			fail("detect:frag_attack kind:flood needs count and seconds")
		}
		if r.fragKind != "" && !flood && (seen["count"] || seen["seconds"]) {
			fail("count and seconds are only valid with kind:flood")
		}
		if seen["min_size"] && r.fragKind != FragTiny && r.fragKind != "" {
			fail("min_size is only valid with kind:tiny")
		}
		if r.minSize == 0 {
			r.minSize = defaultMinFragSize
		}
	case DetectARPSpoof:
		if kind != "" && !slices.Contains(arpKinds, kind) {
			fail("kind %q: want %s", kind, strings.Join(arpKinds, ", "))
			break
		}
		r.arpKind = kind
		counted := slices.Contains(arpCounted, kind)
		if counted && (!seen["count"] || !seen["seconds"]) {
			fail("detect:arp_spoof kind:%s needs count and seconds", kind)
		}
		if kind != "" && !counted && (seen["count"] || seen["seconds"]) {
			fail("count and seconds are only valid with kind:%s", strings.Join(arpCounted, ", kind:"))
		}
		if kind == ARPMultiIP && r.detect.count > maxDistinct {
			fail("kind:multi_ip count %d: at most %d", r.detect.count, maxDistinct)
		}
	case DetectUDPFlood:
		if r.metric == "" {
			r.metric = MetricPackets
		}
		if !seen["max_reply_ratio"] {
			r.maxReplyRatio = defaultMaxReplyRatio
		}
	case DetectICMPFlood:
		if kind != "" && !slices.Contains(icmpKinds, kind) {
			fail("kind %q: want %s", kind, strings.Join(icmpKinds, ", "))
			break
		}
		r.icmpKind = kind
		switch {
		case kind == ICMPEcho && !seen["track"]:
			fail("detect:icmp_flood kind:echo needs track")
		case kind != ICMPEcho && kind != "" && seen["track"]:
			fail("track is only valid with kind:echo (kind:%s always tracks the receiver)", kind)
		}
	}
	for _, k := range []string{"flags", "content", "app_proto", "app_field", "app_reason", "detection_filter",
		"same_ip", "same_port", "eth_dst", "itype", "icode", "ttl", "arp_op", "dsize"} {
		if seenOption(opts, k) {
			fail("option %s cannot be combined with detect", k)
		}
	}
	return sidSet
}

func knownOption(k string) bool {
	switch k {
	case "msg", "sid", "rev", "severity", "category", "flags", "content", "nocase",
		"app_proto", "app_field", "app_reason", "detection_filter", "detect",
		"track", "count", "seconds", "min_incomplete_ratio", "max_distinct_ports",
		"distinct_ports", "distinct_hosts", "same_ip", "same_port", "eth_dst", "itype",
		"icode", "ttl", "kind", "scope", "min_samples", "max_hop_diff", "min_size", "arp_op",
		"dsize", "metric", "max_reply_ratio":
		return true
	}
	return false
}

// noValue lists the options written without ":value".
var noValue = map[string]bool{"nocase": true, "same_ip": true, "same_port": true}

// detectorOptions lists, per detector, the options it needs and the ones
// it may take. seconds is shared; the scan detectors always track by
// source, so they take neither track nor count.
var detectorOptions = map[string]struct{ required, optional []string }{
	DetectSYNFlood:   {required: []string{"track", "count", "seconds"}, optional: []string{"min_incomplete_ratio", "max_distinct_ports"}},
	DetectPortScan:   {required: []string{"distinct_ports", "seconds"}},
	DetectHostSweep:  {required: []string{"distinct_hosts", "seconds"}},
	DetectPingSweep:  {required: []string{"distinct_hosts", "seconds"}},
	DetectTTLAnomaly: {required: []string{"count", "seconds"}, optional: []string{"min_samples", "max_hop_diff", "scope"}},
	// count and seconds are required for kind:flood only; parseOptions
	// checks that.
	DetectFragAttack: {required: []string{"kind"}, optional: []string{"count", "seconds", "min_size"}},
	// count and seconds are required for flip_flop, unsolicited_reply and
	// multi_ip only; parseOptions checks that.
	DetectARPSpoof: {required: []string{"kind"}, optional: []string{"count", "seconds"}},
	DetectUDPFlood: {required: []string{"track", "count", "seconds"}, optional: []string{"metric", "max_reply_ratio"}},
	// track is required for kind:echo only and not allowed for the other
	// kinds; parseOptions checks that.
	DetectICMPFlood:  {required: []string{"kind", "count", "seconds"}, optional: []string{"track"}},
	DetectICMPTunnel: {required: []string{"count", "seconds"}},
}

// detectorsTaking names the detectors that accept option k, for errors.
func detectorsTaking(k string) string {
	var names []string
	for _, d := range []string{DetectSYNFlood, DetectPortScan, DetectHostSweep, DetectPingSweep, DetectTTLAnomaly, DetectFragAttack, DetectARPSpoof,
		DetectUDPFlood, DetectICMPFlood, DetectICMPTunnel} {
		spec := detectorOptions[d]
		if slices.Contains(spec.required, k) || slices.Contains(spec.optional, k) {
			names = append(names, d)
		}
	}
	return strings.Join(names, ", detect:")
}

// checkProtoOptions reports options that cannot apply to r.Proto.
func checkProtoOptions(r *Rule, fail func(string, ...any)) {
	if r.hasFlags && r.Proto != ProtoTCP {
		fail("flags requires protocol tcp")
	}
	switch r.Detect {
	case DetectSYNFlood:
		if r.Proto != ProtoTCP {
			fail("detect:%s requires protocol tcp", r.Detect)
		}
	case DetectPortScan, DetectHostSweep:
		if r.Proto != ProtoIP && r.Proto != ProtoTCP && r.Proto != ProtoUDP {
			fail("detect:%s requires protocol ip, tcp or udp", r.Detect)
		}
	case DetectPingSweep:
		if r.Proto != ProtoIP && r.Proto != ProtoICMP {
			fail("detect:%s requires protocol ip or icmp", r.Detect)
		}
	case DetectTTLAnomaly:
		if r.Proto == ProtoARP {
			fail("detect:%s requires protocol ip, tcp, udp or icmp", r.Detect)
		}
	case DetectFragAttack:
		if r.Proto != ProtoIP {
			fail("detect:%s requires protocol ip", r.Detect)
		}
	case DetectARPSpoof:
		if r.Proto != ProtoARP {
			fail("detect:%s requires protocol arp", r.Detect)
		}
	case DetectUDPFlood:
		if r.Proto != ProtoUDP {
			fail("detect:%s requires protocol udp", r.Detect)
		}
	case DetectICMPFlood, DetectICMPTunnel:
		if r.Proto != ProtoICMP {
			fail("detect:%s requires protocol icmp", r.Detect)
		}
	}
	if r.arpOp != 0 && r.Proto != ProtoARP {
		fail("arp_op requires protocol arp")
	}
	if r.samePort && !hasPortsProto(r.Proto) {
		fail("same_port requires protocol tcp or udp")
	}
	if (r.sameIP || r.ttl.op != 0 || r.dsize.op != 0) && r.Proto == ProtoARP {
		fail("same_ip, ttl and dsize require an IP protocol (ip, tcp, udp or icmp)")
	}
	if (r.hasIType || r.hasICode) && r.Proto != ProtoICMP && r.Proto != ProtoIP {
		fail("itype and icode require protocol icmp or ip")
	}
	if r.Detect != "" && r.Action == ActionPass {
		fail("detect cannot be used with a pass rule")
	}
	if r.filter != nil && r.Action == ActionPass {
		fail("detection_filter cannot be used with a pass rule")
	}
	if (r.appProto != "" || len(r.appFields) > 0 || len(r.appReasons) > 0) && (r.Proto == ProtoICMP || r.Proto == ProtoARP) {
		fail("app_proto, app_field and app_reason require protocol ip, tcp or udp")
	}
}

func hasPortsProto(p Proto) bool { return p == ProtoTCP || p == ProtoUDP }

// parseTTL parses "N", "<N" or ">N". A comparison that no TTL can
// satisfy (<0, >255) is an error.
func parseTTL(v string) (ttlCheck, error) {
	c := ttlCheck{op: '='}
	if v != "" && (v[0] == '<' || v[0] == '>') {
		c.op, v = v[0], v[1:]
	}
	n, err := strconv.ParseUint(v, 10, 8)
	if err != nil {
		return c, fmt.Errorf("%q: want N, <N or >N with N from 0 to 255", v)
	}
	c.n = uint8(n)
	if c.op == '<' && n == 0 || c.op == '>' && n == 255 {
		return c, fmt.Errorf("%c%d matches no TTL", c.op, n)
	}
	return c, nil
}

// parseDsize parses "N", "<N", ">N" or "N<>M" (inclusive), with sizes
// from 0 to 65535. A comparison no payload can satisfy (<0, >65535, or a
// range with N > M) is an error.
func parseDsize(v string) (dsizeCheck, error) {
	whole := v
	num := func(s string) (int, error) {
		n, err := strconv.ParseUint(s, 10, 16)
		if err != nil {
			return 0, fmt.Errorf("%q: want N, <N, >N or N<>M with sizes from 0 to 65535", whole)
		}
		return int(n), nil
	}
	if lo, hi, ok := strings.Cut(v, "<>"); ok {
		a, err := num(lo)
		if err != nil {
			return dsizeCheck{}, err
		}
		b, err := num(hi)
		if err != nil {
			return dsizeCheck{}, err
		}
		if a > b {
			return dsizeCheck{}, fmt.Errorf("%q: range is empty (%d > %d)", v, a, b)
		}
		return dsizeCheck{op: 'r', lo: a, hi: b}, nil
	}
	c := dsizeCheck{op: '='}
	if v != "" && (v[0] == '<' || v[0] == '>') {
		c.op, v = v[0], v[1:]
	}
	n, err := num(v)
	if err != nil {
		return c, err
	}
	c.lo = n
	if c.op == '<' && n == 0 || c.op == '>' && n == 65535 {
		return c, fmt.Errorf("%c%d matches no payload size", c.op, n)
	}
	return c, nil
}

func isName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

func parsePositive(s string, max int) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > max {
		return 0, fmt.Errorf("%q: want an integer from 1 to %d", s, max)
	}
	return n, nil
}

func parseFlags(r *Rule, v string) error {
	if v == "0" {
		r.hasFlags = true
		return nil
	}
	if strings.HasSuffix(v, "+") {
		r.flagsPlus = true
		v = v[:len(v)-1]
	}
	if v == "" {
		return errors.New("no flags given (want letters from SAFRPU, optional '+', or 0)")
	}
	for i := 0; i < len(v); i++ {
		var bit uint8
		switch v[i] {
		case 'S':
			bit = tcpSYN
		case 'A':
			bit = tcpACK
		case 'F':
			bit = tcpFIN
		case 'R':
			bit = tcpRST
		case 'P':
			bit = tcpPSH
		case 'U':
			bit = tcpURG
		default:
			return fmt.Errorf("unknown flag %q (want letters from SAFRPU, optional '+', or 0)", v[i])
		}
		if r.flags&bit != 0 {
			return fmt.Errorf("flag %q repeated", v[i])
		}
		r.flags |= bit
	}
	r.hasFlags = true
	return nil
}

// parseDetectionFilter parses "track by_src, count N, seconds S".
func parseDetectionFilter(v string) (windowSpec, error) {
	var ws windowSpec
	seen := make(map[string]bool)
	for _, part := range strings.Split(v, ",") {
		f := strings.Fields(part)
		if len(f) != 2 {
			return ws, fmt.Errorf("%q: want \"track by_src|by_dst, count N, seconds S\"", strings.TrimSpace(part))
		}
		if seen[f[0]] {
			return ws, fmt.Errorf("%s given more than once", f[0])
		}
		seen[f[0]] = true
		var err error
		switch f[0] {
		case "track":
			switch f[1] {
			case "by_src":
				ws.track = TrackBySrc
			case "by_dst":
				ws.track = TrackByDst
			default:
				return ws, fmt.Errorf("track %q: want by_src or by_dst", f[1])
			}
		case "count":
			ws.count, err = parsePositive(f[1], maxCount)
		case "seconds":
			ws.seconds, err = parsePositive(f[1], maxSeconds)
		default:
			return ws, fmt.Errorf("unknown term %q (want track, count, seconds)", f[0])
		}
		if err != nil {
			return ws, fmt.Errorf("%s %v", f[0], err)
		}
	}
	for _, k := range []string{"track", "count", "seconds"} {
		if !seen[k] {
			return ws, fmt.Errorf("missing %s", k)
		}
	}
	return ws, nil
}

// unquote decodes a "..." string with the escapes \" \\ and \;.
func unquote(v string) (string, error) {
	if len(v) < 2 || v[0] != '"' || v[len(v)-1] != '"' {
		return "", fmt.Errorf("%s: want a double-quoted string", v)
	}
	in := v[1 : len(v)-1]
	var b strings.Builder
	for i := 0; i < len(in); i++ {
		c := in[i]
		switch {
		case c == '\\':
			if i+1 >= len(in) {
				return "", errors.New("string ends with a lone backslash")
			}
			i++
			switch in[i] {
			case '"', '\\', ';':
				b.WriteByte(in[i])
			default:
				return "", fmt.Errorf("unknown escape \\%c (want \\\", \\\\ or \\;)", in[i])
			}
		case c == '"':
			return "", errors.New("unescaped '\"' inside string")
		default:
			b.WriteByte(c)
		}
	}
	return b.String(), nil
}

// parseContent decodes a content string: like unquote, plus \| and
// |hex bytes| sections such as |0d 0a|.
func parseContent(v string) ([]byte, error) {
	if len(v) < 2 || v[0] != '"' || v[len(v)-1] != '"' {
		return nil, fmt.Errorf("%s: want a double-quoted string", v)
	}
	in := v[1 : len(v)-1]
	var out []byte
	for i := 0; i < len(in); i++ {
		c := in[i]
		switch c {
		case '\\':
			if i+1 >= len(in) {
				return nil, errors.New("string ends with a lone backslash")
			}
			i++
			switch in[i] {
			case '"', '\\', ';', '|':
				out = append(out, in[i])
			default:
				return nil, fmt.Errorf("unknown escape \\%c (want \\\", \\\\, \\; or \\|)", in[i])
			}
		case '"':
			return nil, errors.New("unescaped '\"' inside string")
		case '|':
			end := strings.IndexByte(in[i+1:], '|')
			if end < 0 {
				return nil, errors.New("unterminated |hex| section")
			}
			hex := in[i+1 : i+1+end]
			i += end + 1
			digits := strings.Join(strings.Fields(hex), "")
			if digits == "" {
				return nil, errors.New("empty |hex| section")
			}
			for _, word := range strings.Fields(hex) {
				if len(word)%2 != 0 {
					return nil, fmt.Errorf("hex %q: odd number of digits", word)
				}
			}
			for j := 0; j < len(digits); j += 2 {
				n, err := strconv.ParseUint(digits[j:j+2], 16, 8)
				if err != nil {
					return nil, fmt.Errorf("bad hex byte %q", digits[j:j+2])
				}
				out = append(out, byte(n))
			}
		default:
			out = append(out, c)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("empty content")
	}
	return out, nil
}

// parseAddrSpec parses any, an address, a CIDR prefix or a [list], each
// optionally negated with '!'.
func parseAddrSpec(s string) (addrSpec, error) {
	var spec addrSpec
	if strings.HasPrefix(s, "!") {
		spec.neg = true
		s = s[1:]
	}
	if s == "any" {
		if spec.neg {
			return spec, errors.New("!any matches nothing")
		}
		spec.any = true
		return spec, nil
	}
	if strings.HasPrefix(s, "[") || strings.HasSuffix(s, "]") {
		if !strings.HasPrefix(s, "[") || !strings.HasSuffix(s, "]") || len(s) < 2 {
			return spec, fmt.Errorf("%q: unbalanced brackets", s)
		}
		inner := s[1 : len(s)-1]
		if strings.TrimSpace(inner) == "" {
			return spec, errors.New("empty list")
		}
		for _, item := range strings.Split(inner, ",") {
			neg := strings.HasPrefix(item, "!")
			if neg {
				item = item[1:]
			}
			if item == "" {
				return spec, fmt.Errorf("%q: empty list item", s)
			}
			if item == "any" || strings.ContainsAny(item, "[]!") {
				return spec, fmt.Errorf("%q: list items must be addresses or prefixes", item)
			}
			p, err := parsePrefix(item)
			if err != nil {
				return spec, err
			}
			if neg {
				spec.negs = append(spec.negs, p)
			} else {
				spec.pos = append(spec.pos, p)
			}
		}
		return spec, nil
	}
	p, err := parsePrefix(s)
	if err != nil {
		return spec, err
	}
	spec.pos = []netip.Prefix{p}
	return spec, nil
}

func parsePrefix(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("invalid CIDR %q", s)
		}
		if p.Addr().Is4In6() {
			return netip.Prefix{}, fmt.Errorf("%q: write IPv4 prefixes in dotted form", s)
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" {
		return netip.Prefix{}, fmt.Errorf("invalid address %q", s)
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// parsePortSpec parses any, N, N:M, N:, :M or a [list] of those, each
// optionally negated with '!'.
func parsePortSpec(s string) (portSpec, error) {
	var spec portSpec
	if strings.HasPrefix(s, "!") {
		spec.neg = true
		s = s[1:]
	}
	if s == "any" {
		if spec.neg {
			return spec, errors.New("!any matches nothing")
		}
		spec.any = true
		return spec, nil
	}
	if strings.HasPrefix(s, "[") || strings.HasSuffix(s, "]") {
		if !strings.HasPrefix(s, "[") || !strings.HasSuffix(s, "]") || len(s) < 2 {
			return spec, fmt.Errorf("%q: unbalanced brackets", s)
		}
		inner := s[1 : len(s)-1]
		if strings.TrimSpace(inner) == "" {
			return spec, errors.New("empty list")
		}
		for _, item := range strings.Split(inner, ",") {
			neg := strings.HasPrefix(item, "!")
			if neg {
				item = item[1:]
			}
			if item == "" {
				return spec, fmt.Errorf("%q: empty list item", s)
			}
			if item == "any" || strings.ContainsAny(item, "[]!") {
				return spec, fmt.Errorf("%q: list items must be ports or ranges", item)
			}
			r, err := parsePortRange(item)
			if err != nil {
				return spec, err
			}
			if neg {
				spec.negs = append(spec.negs, r)
			} else {
				spec.pos = append(spec.pos, r)
			}
		}
		return spec, nil
	}
	r, err := parsePortRange(s)
	if err != nil {
		return spec, err
	}
	spec.pos = []portRange{r}
	return spec, nil
}

func parsePortRange(s string) (portRange, error) {
	lo, hi, isRange := strings.Cut(s, ":")
	if !isRange {
		p, err := parsePort(s)
		return portRange{p, p}, err
	}
	if lo == "" && hi == "" {
		return portRange{}, fmt.Errorf("invalid port range %q", s)
	}
	r := portRange{0, 65535}
	var err error
	if lo != "" {
		if r.lo, err = parsePort(lo); err != nil {
			return r, err
		}
	}
	if hi != "" {
		if r.hi, err = parsePort(hi); err != nil {
			return r, err
		}
	}
	if r.lo > r.hi {
		return r, fmt.Errorf("port range %q: start is after end", s)
	}
	return r, nil
}

func parsePort(s string) (uint16, error) {
	n, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("invalid port %q (want 0-65535)", s)
	}
	return uint16(n), nil
}
