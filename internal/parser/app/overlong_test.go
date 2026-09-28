package app

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestDecodeOverlong(t *testing.T) {
	tests := []struct {
		in, want string
		found    bool
	}{
		{"", "", false},
		{"/plain/../path", "/plain/../path", false},
		{"\xc0\xae", ".", true},
		{"\xc0\xaf", "/", true},
		{"\xc1\x9c", "\\", true},                // IIS: ..%c1%9c
		{"\xe0\x80\xae", ".", true},             // 3-byte '.'
		{"\xf0\x80\x80\xae", ".", true},         // 4-byte '.'
		{"\xe0\x82\x80", "\u0080", true},        // 3-byte U+0080: overlong, re-encoded in 2 bytes
		{"\xf0\x8f\xbf\xbf", "￿", true},         // 4-byte U+FFFF
		{"\xc2\xae", "\xc2\xae", false},         // U+00AE, valid
		{"\xe0\xa0\x80", "\xe0\xa0\x80", false}, // U+0800, the first valid 3-byte
		{"\xf0\x90\x80\x80", "\xf0\x90\x80\x80", false},
		{"\xc0", "\xc0", false},         // truncated
		{"\xc0A", "\xc0A", false},       // not a continuation
		{"\xe0\x80", "\xe0\x80", false}, // truncated 3-byte
		{"\xc0\xc0\xae", "\xc0.", true}, // a stray lead byte before an overlong
		{"a\xc0\xae\xc0\xaeb", "a..b", true},
	}
	for _, tt := range tests {
		got, found := decodeOverlong(tt.in)
		if got != tt.want || found != tt.found {
			t.Errorf("decodeOverlong(%q) = %q, %v; want %q, %v", tt.in, got, found, tt.want, tt.found)
		}
	}
}

// FuzzDecodeOverlong checks that the decoder never grows its input, is
// the identity when it finds nothing, leaves no overlong sequence behind
// and is idempotent.
func FuzzDecodeOverlong(f *testing.F) {
	for _, s := range []string{"", "/a/%c0%ae", "\xc0\xae\xc0\xaf", "\xe0\x80\xae", "\xf0\x80\x80\xae", "\xc0\xc0\xae", "café", "\xe0\x82\x80\xc0"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		out, found := decodeOverlong(in)
		if len(out) > len(in) {
			t.Fatalf("grew: %q -> %q", in, out)
		}
		if !found && out != in {
			t.Fatalf("changed without finding: %q -> %q", in, out)
		}
		if found == (out == in) && found {
			t.Fatalf("found but unchanged: %q", in)
		}
		for i := 0; i < len(out); i++ {
			if _, n := overlongAt(out, i); n != 0 {
				t.Fatalf("overlong left at %d: %q -> %q", i, in, out)
			}
		}
		if again, f2 := decodeOverlong(out); f2 || again != out {
			t.Fatalf("not idempotent: %q -> %q -> %q", in, out, again)
		}
		if utf8.ValidString(in) && found {
			t.Fatalf("valid UTF-8 reported overlong: %q", in)
		}
		if strings.Count(out, "�") > strings.Count(in, "�") {
			t.Fatalf("replacement characters introduced: %q", out)
		}
	})
}
