package rules

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"math"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"github.com/bUrn-1337/intrusion-detection-system/internal/packet"
)

// Limits on numeric option values. count bounds the per-key deque, so it
// also bounds memory.
const (
	maxCount   = 100000
	maxSeconds = 86400
	maxLineLen = 1 << 20
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
		rules   []*Rule
		errs    []*SyntaxError
		sidLine = make(map[int]int)
		lineNo  int
	)
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		rule, reasons := parseRule(line)
		if rule != nil {
			if first, dup := sidLine[rule.SID]; dup {
				reasons = append(reasons, fmt.Sprintf("duplicate sid %d (first defined on line %d)", rule.SID, first))
			} else {
				sidLine[rule.SID] = lineNo
			}
		}
		for _, reason := range reasons {
			errs = append(errs, &SyntaxError{File: name, Line: lineNo, Reason: reason})
		}
		if rule != nil && len(reasons) == 0 {
			rule.File, rule.Line = name, lineNo
			rules = append(rules, rule)
		}
	}
	if err := sc.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			errs = append(errs, &SyntaxError{File: name, Line: lineNo + 1, Reason: fmt.Sprintf("line longer than %d bytes", maxLineLen)})
		} else {
			return nil, err
		}
	}
	if len(errs) > 0 {
		return nil, &LoadError{Errors: errs}
	}
	return newRuleSet(name, rules), nil
}

// parseRule parses one non-comment line. It returns every problem found.
// The rule is nil only when the SID could not be determined, so duplicate
// SIDs are still detected on lines with other errors.
func parseRule(line string) (*Rule, []string) {
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

	r := &Rule{Rev: 1, Severity: SeverityMedium, text: strings.Join(strings.Fields(line), " ")}
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
	sidSet := parseOptions(r, opts, fail)

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
func parseOptions(r *Rule, opts []option, fail func(string, ...any)) bool {
	var (
		sidSet     bool
		seen       = make(map[string]bool)
		lastContnt = -1 // index into r.contents that nocase applies to
		nocaseDone = make(map[int]bool)
		detectOpts []string
	)
	once := map[string]bool{
		"msg": true, "sid": true, "rev": true, "severity": true, "category": true,
		"flags": true, "app_proto": true, "detection_filter": true, "detect": true,
		"track": true, "count": true, "seconds": true, "min_incomplete_ratio": true,
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
		if o.key != "nocase" && !o.hasValue {
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
			case o.hasValue:
				fail("nocase takes no value")
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
			if v != DetectSYNFlood {
				fail("detect %q: the only detector is %s", v, DetectSYNFlood)
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
			n, err := parsePositive(v, maxCount)
			if err != nil {
				fail("count: %v", err)
				continue
			}
			r.detect.count = n
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
		default:
			fail("unknown option %q", o.key)
		}
	}

	if r.Detect == "" {
		if len(detectOpts) > 0 {
			fail("option %s is only valid with detect:%s", detectOpts[0], DetectSYNFlood)
		}
		return sidSet
	}
	// Detector rule.
	var missing []string
	for _, k := range []string{"track", "count", "seconds"} {
		if !seen[k] {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		fail("detect:%s needs %s", DetectSYNFlood, strings.Join(missing, ", "))
	}
	if !ratio {
		r.minRatio = 0.8
	}
	for _, k := range []string{"flags", "content", "app_proto", "app_field", "app_reason", "detection_filter"} {
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
		"track", "count", "seconds", "min_incomplete_ratio":
		return true
	}
	return false
}

// checkProtoOptions reports options that cannot apply to r.Proto.
func checkProtoOptions(r *Rule, fail func(string, ...any)) {
	if r.hasFlags && r.Proto != ProtoTCP {
		fail("flags requires protocol tcp")
	}
	if r.Detect != "" && r.Proto != ProtoTCP {
		fail("detect:%s requires protocol tcp", r.Detect)
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
