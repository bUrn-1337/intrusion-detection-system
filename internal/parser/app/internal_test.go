package app

import (
	"errors"
	"strings"
	"testing"

	"github.com/bUrn-1337/intrusion-detection-system/internal/entropy"
)

// chainMsg returns a message whose bytes at 0 are a root label and whose
// following 2-byte words are pointers, each to the previous one. Decoding
// from the last pointer follows n jumps.
func chainMsg(n int) (msg []byte, start int) {
	msg = []byte{0}
	for k := 0; k < n; k++ {
		target := 0
		if k > 0 {
			target = 1 + 2*(k-1)
		}
		msg = append(msg, 0xC0|byte(target>>8), byte(target))
	}
	return msg, 1 + 2*(n-1)
}

func TestDecodeName(t *testing.T) {
	chain16, start16 := chainMsg(maxPointerJumps)
	chain17, start17 := chainMsg(maxPointerJumps + 1)
	// "example.com" at 0, then "www" + pointer to 0 at 13.
	compressed := append([]byte("\x07example\x03com\x00"), "\x03www\xC0\x00"...)
	name255 := strings.Repeat("\x3F"+strings.Repeat("a", 63), 3) + "\x3D" + strings.Repeat("b", 61) + "\x00"
	name256 := strings.Repeat("\x3F"+strings.Repeat("a", 63), 3) + "\x3E" + strings.Repeat("b", 62) + "\x00"

	tests := []struct {
		name     string
		msg      []byte
		off      int
		want     string
		wantNext int
		err      error
	}{
		{name: "root", msg: []byte{0}, want: ".", wantNext: 1},
		{name: "plain", msg: []byte("\x07example\x03com\x00rest"), want: "example.com", wantNext: 13},
		{name: "backward pointer", msg: compressed, off: 13, want: "www.example.com", wantNext: 19},
		{name: "pointer only", msg: compressed, off: 17, want: "example.com", wantNext: 19},
		{name: "forward pointer", msg: []byte("\xC0\x02\x00"), err: errCompressionLoop},
		{name: "self pointer", msg: []byte("\x01a\xC0\x02"), err: errCompressionLoop},
		{name: "pointer loop via label", msg: []byte("\x01a\xC0\x00"), err: errTooManyJumps},
		{name: "16 jumps is the cap", msg: chain16, off: start16, want: ".", wantNext: start16 + 2},
		{name: "17 jumps", msg: chain17, off: start17, err: errTooManyJumps},
		{name: "label of 63", msg: []byte("\x3F" + strings.Repeat("x", 63) + "\x00"), want: strings.Repeat("x", 63), wantNext: 65},
		{name: "label of 64", msg: []byte("\x40" + strings.Repeat("x", 64) + "\x00"), err: errLabelTooLong},
		{name: "extended label type 01", msg: []byte("\x41\x00"), err: errLabelTooLong},
		{name: "reserved label type 10", msg: []byte("\x80\x00"), err: errReservedLabel},
		{name: "255 bytes", msg: []byte(name255), want: strings.Repeat(strings.Repeat("a", 63)+".", 3) + strings.Repeat("b", 61), wantNext: 255},
		{name: "256 bytes", msg: []byte(name256), err: errNameTooLong},
		{name: "missing root", msg: []byte("\x03com"), err: errNameTruncated},
		{name: "label past end", msg: []byte("\x05ab"), err: errNameTruncated},
		{name: "half a pointer", msg: []byte("\x01a\xC0"), err: errNameTruncated},
		{name: "offset past end", msg: []byte{0}, off: 1, err: errNameTruncated},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			labels, next, err := decodeName(tt.msg, tt.off)
			if !errors.Is(err, tt.err) {
				t.Fatalf("err = %v, want %v", err, tt.err)
			}
			if err != nil {
				return
			}
			if got := nameString(labels); got != tt.want {
				t.Errorf("name = %q, want %q", got, tt.want)
			}
			if next != tt.wantNext {
				t.Errorf("next = %d, want %d", next, tt.wantNext)
			}
		})
	}
}

func TestNameString(t *testing.T) {
	got := nameString([][]byte{[]byte("A.b\\C"), {0x00, ' ', 0xFF}, []byte("Com")})
	if want := `a\.b\\c.\000\032\255.com`; got != want {
		t.Errorf("nameString = %q, want %q", got, want)
	}
}

func TestLabelEntropyThreshold(t *testing.T) {
	// Tunnel-style labels score above the threshold; long ordinary ones
	// below it.
	for _, s := range []string{"nbswy3dpeb3w64tmmqqgc3tqmfzxg4dxn5zgs3tomv2gs5dv", "4f6b1c9e2a7d3f8b0c5e1a9d7f2b6c3e8a0d4f1b"} {
		if h := entropy.Shannon([]byte(s)); h <= suspiciousLabelEntropy {
			t.Errorf("Shannon(%q) = %.2f, want > %v", s, h, suspiciousLabelEntropy)
		}
	}
	// Low-diversity labels stay below it. Note that 40+ character labels
	// of ordinary hostname text also score about 3.7 (for example
	// "www-downloads-mirror-server-eu-west-1-cdn"), so at 3.5 the rule is
	// a weak signal on its own.
	for _, s := range []string{strings.Repeat("ab", 30), "aaaaaaaaaabbbbbbbbbbccccccccccdddddddddd-e"} {
		if h := entropy.Shannon([]byte(s)); h > suspiciousLabelEntropy {
			t.Errorf("Shannon(%q) = %.2f, want <= %v", s, h, suspiciousLabelEntropy)
		}
	}
}

func TestPercentDecode(t *testing.T) {
	tests := []struct{ in, want string }{
		{"/plain", "/plain"},
		{"/a%20b", "/a b"},
		{"%41%62%7a%7A", "Abzz"},
		{"%252e", "%2e"},
		{"%2", "%2"},
		{"%zz%", "%zz%"},
		{"100%", "100%"},
		{"a+b", "a+b"},
		{"%00", "\x00"},
	}
	for _, tt := range tests {
		if got := percentDecode(tt.in); got != tt.want {
			t.Errorf("percentDecode(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func FuzzDNSName(f *testing.F) {
	chain, start := chainMsg(maxPointerJumps + 1)
	f.Add(chain, start)
	f.Add([]byte("\x07example\x03com\x00\x03www\xC0\x00"), 13)
	f.Add([]byte("\xC0\x00"), 0)
	f.Add([]byte("\x80\x00"), 0)
	f.Add([]byte("\x3F"+strings.Repeat("x", 63)+"\x00"), 0)
	f.Fuzz(func(t *testing.T, msg []byte, off int) {
		labels, next, err := decodeName(msg, off)
		if err != nil {
			if labels != nil {
				t.Error("labels returned with an error")
			}
			return
		}
		if next <= off || next > len(msg) {
			t.Errorf("next = %d, off %d, len %d", next, off, len(msg))
		}
		wire := 1
		for _, l := range labels {
			if len(l) == 0 || len(l) > maxLabelLen {
				t.Errorf("label length %d", len(l))
			}
			wire += 1 + len(l)
		}
		if wire > maxNameLen {
			t.Errorf("wire length %d", wire)
		}
		s := nameString(labels)
		if s != strings.ToLower(s) {
			t.Errorf("name not lowercase: %q", s)
		}
	})
}

// Benign double-encoded URIs, shortened from the 11 requests in the public
// lotsofweb.pcapng capture that the old "decodes twice" check flagged: ad
// click trackers, analytics beacons and Google Analytics cookies carry an
// encoded URL or cookie inside a query parameter.
var benignDoubleEncoded = []string{
	"/1413310/ad-336x280.swf?clickTag=http%3A//ad.example.test/click%253Bh%3Dv8/38ed/3/0/%252a/a%253B219492202%253B0-0%253B0",
	"/1420759/ad-300x250.swf?ct=US&clickTAG=http%3A//ad.example.test/click%253Bh%3Dv8/38ed/f/17a/%252a/v%253B218777608%253B1-0",
	"/1413310/ad-336x280.swf?clickTag=http%3A//ad.example.test/click%253B%253B%257Eokv%253D%253B%2521category%253D%253Bs%253D8_10006",
	"/1420759/ad-300x250.swf?clickTAG=http%3A//ad.example.test/click%253B%253B%257Esscs%253D%253fhttp%253A%252F%252Fshop.example.test%252F",
	"/A09801/b3/0/3/0902121/139683317.js?D=DM_LOC%3Dhttp%253A%252F%252Fwww.example.test%252FWORLD%252F%253Fundefined%253Dundefined%26DM_CAT%3Dnews%2520%253E%2520world",
	"/A09801/b3/0/3/0902121/934627693.js?D=DM_LOC%3Dhttp%253A%252F%252Fwww.example.test%252F%253Fundefined%253Dundefined%26DM_CAT%3Dnews%2520%253E%2520homepage%26DM_EOM%3D1",
	"/A09801/b3/0/3/0902121/989450581.js?D=DM_LOC%3Dhttp%253A%252F%252Fwww.example.test%252F%26DM_REF%3Dhttp%253A%252F%252Fwww.example.test%252F%26DM_EOM%3D1&C=A09801",
	"/__utm.gif?utmwv=4.5.9&utmhn=social.example.test&utmt=var&utmcc=__utma%3D43838368.1980854511.1258909459.1%3B%2B__utmv%3D43838368.Not%2520Logged%2520In%3B",
	"/__utm.gif?utmwv=4.5.9&utmhn=social.example.test&utmp=%2F&utmcc=__utma%3D43838368.1980854511.1258909459.1%3B%2B__utmz%3D43838368.utmcsr%3D(direct)%7Cutmcmd%3D(none)%3B%2B__utmv%3D43838368.Not%2520Logged%2520In%3B",
	"/__utm.gif?utmwv=4.5.9&utmhn=social.example.test&utmt=var&utmcc=__utma%3D43838368.1980854511.1258909459.1%3B%2B__utmv%3D43838368.lang%253A%2520en%3B",
	"/__utm.gif?utmwv=4.5.9&utmn=707020248&utmhn=social.example.test&utmcc=__utmz%3D43838368.utmcsr%3D(direct)%7Cutmccn%3D(direct)%3B%2B__utmv%3D43838368.lang%253A%2520en%3B",
}

func TestHidesTraversal(t *testing.T) {
	for _, uri := range benignDoubleEncoded {
		decoded := percentDecode(uri)
		if percentDecode(decoded) == decoded {
			t.Errorf("test URI is not double-encoded, so it tests nothing: %q", uri)
		}
		if hidesTraversal(decoded) {
			t.Errorf("hidesTraversal flags benign %q", uri)
		}
	}

	tests := []struct {
		uri  string
		want bool
	}{
		{"/static/%252e%252e%252f%252e%252e%252fetc%252fpasswd", true},
		{"/a/%252e%252e/%252e%252e/etc/passwd", true},         // "../" appears after the second decode
		{"/cgi-bin/%252e%252e%255cwindows%255cwin.ini", true}, // "..\"
		{"/download?file=report.pdf%2500.php", true},          // NUL
		{"/%25252e%25252e%25252fetc/passwd", true},            // triple encoding
		{"/x/../%252e%252e%252fsecret", true},                 // a hidden one next to a plain one
		{"/x/../y/%252Fz", false},                             // the "../" was already visible
		{"/a%20b", false},                                     // single encoding
		{"/search?q=50%25+off", false},                        // an escaped percent sign
		{"/p?u=http%253A%252F%252Fexample.test%252F", false},  // an encoded URL, no traversal
		{"/p?v=..%252e", false},                               // decodes to "..." with no separator
		{"/%252e%252e", false},                                // ".." alone, no separator
	}
	for _, tt := range tests {
		if got := hidesTraversal(percentDecode(tt.uri)); got != tt.want {
			t.Errorf("hidesTraversal(decode(%q)) = %v, want %v", tt.uri, got, tt.want)
		}
	}
}
