package rules

import (
	"slices"
	"strings"
	"testing"
)

func TestAppContentRegexParse(t *testing.T) {
	const hdr = "alert tcp any any -> any any "
	r := one(t, hdr+`(msg:"m"; sid:1; app_content:uri,"UNION"; app_content:user_agent, "Sql|4d|ap" , nocase; regex:query,"(?i)\bunion\b.+\bselect\b"; regex:data,"a\"b\;c\\d";)`)
	if len(r.appContents) != 2 || r.appContents[0] != (appContent{"uri", "UNION", false}) || r.appContents[1] != (appContent{"user_agent", "sqlmap", true}) {
		t.Errorf("app_content %+v", r.appContents)
	}
	if len(r.fieldRegex) != 1 || r.fieldRegex[0].key != "query" || r.fieldRegex[0].re.String() != `(?i)\bunion\b.+\bselect\b` {
		t.Errorf("field regex %+v", r.fieldRegex)
	}
	if len(r.dataRegex) != 1 || r.dataRegex[0].String() != `a"b;c\\d` {
		t.Errorf("data regex %v", r.dataRegex)
	}
	if !r.perMessage() {
		t.Error("perMessage false")
	}
	// regex:data on icmp is allowed: it reads the payload.
	one(t, `alert icmp any any -> any any (msg:"m"; sid:1; regex:data,"x+";)`)
}

func TestAppContentRegexErrors(t *testing.T) {
	const hdr = "alert tcp any any -> any any "
	tests := []struct{ line, want string }{
		{hdr + `(msg:"m"; sid:1; regex:uri,"a(";)`, `2: regex: error parsing regexp: missing closing ): ` + "`a(`"},
		{hdr + `(msg:"m"; sid:1; regex:uri,"(?P<x";)`, `2: regex: error parsing regexp`},
		{hdr + `(msg:"m"; sid:1; regex:uri,"a\1";)`, `2: regex: error parsing regexp: invalid escape sequence`},
		{hdr + `(msg:"m"; sid:1; regex:uri,"";)`, `2: regex: empty pattern`},
		{hdr + `(msg:"m"; sid:1; regex:uri,"a",nocase;)`, `use (?i) for case-insensitive`},
		{hdr + `(msg:"m"; sid:1; regex:uri;)`, `2: regex: "uri": want KEY,"..."`},
		{hdr + `(msg:"m"; sid:1; regex:a.b,"x";)`, `key "a.b"`},
		{hdr + `(msg:"m"; sid:1; regex:uri,"x\";)`, `unterminated quoted string`},
		{hdr + `(msg:"m"; sid:1; app_content:uri,"";)`, `2: app_content: empty`},
		{hdr + `(msg:"m"; sid:1; app_content:uri,x;)`, `want KEY,"..."`},
		{hdr + `(msg:"m"; sid:1; app_content:uri,"x",NOCASE;)`, `want nocase or nothing`},
		{hdr + `(msg:"m"; sid:1; app_content:uri,"x" y;)`, `unexpected "y" after the string`},
		{hdr + `(msg:"m"; sid:1; app_content:uri,"|zz|";)`, `bad hex byte`},
		{`alert icmp any any -> any any (msg:"m"; sid:1; app_content:uri,"x";)`, `require protocol ip, tcp or udp`},
		{`alert icmp any any -> any any (msg:"m"; sid:1; regex:uri,"x";)`, `require protocol ip, tcp or udp`},
		{`alert arp any any -> any any (msg:"m"; sid:1; regex:data,"x";)`, `regex:data requires an IP protocol`},
		{hdr + `(msg:"m"; sid:1; detect:syn_flood; track:by_src; count:5; seconds:1; regex:data,"x";)`, `option regex cannot be combined with detect`},
		{hdr + `(msg:"m"; sid:1; detect:syn_flood; track:by_src; count:5; seconds:1; app_content:uri,"x";)`, `option app_content cannot be combined with detect`},
	}
	for _, tt := range tests {
		errs := loadErrors(t, "\n"+tt.line)
		if !slices.ContainsFunc(errs, func(e string) bool { return strings.Contains(e, tt.want) }) {
			t.Errorf("%s\n got %q\nwant %q", tt.line, errs, tt.want)
		}
		for _, e := range errs {
			if !strings.HasPrefix(e, "2: ") {
				t.Errorf("%s: error without its line: %q", tt.line, e)
			}
		}
	}
}

func TestAppContentRegexMatch(t *testing.T) {
	const (
		c = "10.0.0.1"
		s = "10.0.0.2"
	)
	http := func(req string) pkt {
		return pkt{proto: "tcp", src: c, dst: s, sport: 40000, dport: 80, flags: "PA", seq: 1, ack: 1, payload: req}
	}
	union := http("GET /p?id=1+UNION+ALL+SELECT+user,pass+FROM+users HTTP/1.1\r\nHost: a\r\nUser-Agent: sqlmap/1.8\r\n\r\n")
	shoes := http("GET /search?q=select+shoes HTTP/1.1\r\nHost: a\r\n\r\n")
	const hdr = "alert tcp any any -> any any (msg:\"m\"; "
	tests := []struct {
		name string
		rule string
		p    pkt
		want bool
	}{
		{"app_content case-sensitive", hdr + `app_content:uri,"UNION";`, union, true},
		{"app_content case-sensitive miss", hdr + `app_content:uri,"union";`, union, false},
		{"app_content nocase", hdr + `app_content:query,"union all",nocase;`, union, true},
		{"app_content missing key", hdr + `app_content:status_code,"2";`, union, false},
		{"app_content user agent", hdr + `app_content:user_agent,"SQLMAP",nocase;`, union, true},
		{"app_content two must both match", hdr + `app_content:uri,"UNION"; app_content:host,"b";`, union, false},
		{"regex on query", hdr + `regex:query,"(?i)\bunion\b.*\bselect\b";`, union, true},
		{"regex on query needs structure", hdr + `regex:query,"(?i)\bunion\b.*\bselect\b";`, shoes, false},
		{"regex on headers_raw", hdr + `regex:headers_raw,"(?m)^User-Agent: sqlmap";`, union, true},
		{"regex data", hdr + `regex:data,"^GET /p\?id=1";`, union, true},
		{"regex data miss", hdr + `regex:data,"^POST";`, union, false},
		{"regex with app_field", hdr + `app_field:method=GET; regex:uri,"id=\d";`, union, true},
		{"regex with wrong app_field", hdr + `app_field:method=POST; regex:uri,"id=\d";`, union, false},
		{"regex data on udp payload", "alert udp any any -> any any (msg:\"m\"; " + `regex:data,"^hello";`,
			pkt{proto: "udp", src: c, dst: s, sport: 1, dport: 2, payload: "hello world"}, true},
	}
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := tt.rule + " sid:" + string(rune('1'+i%9)) + ";)"
			got := len(firing(t, rule, tt.p)) > 0
			if got != tt.want {
				t.Errorf("fired = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestRegexInputCap checks that only the first maxRegexInput bytes are
// searched, both for data and for a field.
func TestRegexInputCap(t *testing.T) {
	udp := func(payload string) pkt {
		return pkt{proto: "udp", src: "10.0.0.1", dst: "10.0.0.2", sport: 1, dport: 2, payload: payload}
	}
	rule := `alert udp any any -> any any (msg:"m"; sid:1; regex:data,"EVIL";)`
	at := func(off int) string { return strings.Repeat("a", off) + "EVIL" + strings.Repeat("a", 100) }
	if len(firing(t, rule, udp(at(maxRegexInput-4)))) != 1 {
		t.Error("match ending at the cap missed")
	}
	if len(firing(t, rule, udp(at(maxRegexInput-3)))) != 0 {
		t.Error("match past the cap found")
	}

	r := one(t, `alert tcp any any -> any any (msg:"m"; sid:1; regex:uri,"EVIL";)`)
	if !r.matchApp(map[string]string{"uri": at(maxRegexInput - 4)}) {
		t.Error("field match ending at the cap missed")
	}
	if r.matchApp(map[string]string{"uri": at(maxRegexInput - 3)}) {
		t.Error("field read past the cap")
	}
}

func TestContainsASCII(t *testing.T) {
	for _, tt := range []struct {
		s, pat string
		fold   bool
		want   bool
	}{
		{"SqlMap/1.0", "sqlmap", true, true},
		{"SqlMap/1.0", "sqlmap", false, false},
		{"abc", "", true, true},
		{"ab", "abc", true, false},
		{"xxABC", "abc", true, true},
		{"ÄBC", "äbc", true, false}, // ASCII only
	} {
		if got := containsASCII(tt.s, tt.pat, tt.fold); got != tt.want {
			t.Errorf("containsASCII(%q, %q, %v) = %v", tt.s, tt.pat, tt.fold, got)
		}
	}
}
