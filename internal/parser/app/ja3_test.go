package app_test

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/bUrn-1337/intrusion-detection-system/internal/packet"
)

// hello builds a ClientHello record with the given legacy_version, cipher
// suites and extensions (nil exts: no extensions block).
func hello(version uint16, ciphers []uint16, exts ...[]byte) []byte {
	var cs []byte
	for _, c := range ciphers {
		cs = append(cs, u16(c)...)
	}
	body := cat(u16(version), bytes.Repeat([]byte{0x42}, 32), []byte{0},
		u16(uint16(len(cs))), cs, []byte{1, 0})
	if exts != nil {
		e := cat(exts...)
		body = cat(body, u16(uint16(len(e))), e)
	}
	hs := cat([]byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body)
	return cat([]byte{22, 3, 1}, u16(uint16(len(hs))), hs)
}

func groupsExt(groups ...uint16) []byte {
	var b []byte
	for _, g := range groups {
		b = append(b, u16(g)...)
	}
	return ext(10, cat(u16(uint16(len(b))), b))
}

func pointsExt(formats ...byte) []byte {
	return ext(11, cat([]byte{byte(len(formats))}, formats))
}

func md5hex(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

func ja3Of(t *testing.T, rec []byte) (string, string) {
	t.Helper()
	p := parse(tcp4(40000, 443, string(rec)))
	if p.AppProtocol != packet.AppTLS {
		t.Fatalf("AppProtocol %q, fields %v, errs %q", p.AppProtocol, p.AppFields, p.ParseErrors)
	}
	return p.AppFields["ja3"], p.AppFields["ja3_hash"]
}

// The two examples in the JA3 reference README
// (github.com/salesforce/ja3, README.md), rebuilt as ClientHellos.
func TestJA3ReferenceVectors(t *testing.T) {
	for _, tc := range []struct {
		name      string
		rec       []byte
		str, hash string
	}{
		{
			name: "README example",
			rec: hello(769, []uint16{47, 53, 5, 10, 49161, 49162, 49171, 49172, 50, 56, 19, 4},
				sniExt("example.com"), groupsExt(23, 24, 25), pointsExt(0)),
			str:  "769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0",
			hash: "ada70206e40642a3e4461f35503241d5",
		},
		{
			name: "no extensions",
			rec:  hello(769, []uint16{4, 5, 10, 9, 100, 98, 3, 6, 19, 18, 99}),
			str:  "769,4-5-10-9-100-98-3-6-19-18-99,,,",
			hash: "de350869b8c85de67a350c8d186f11e6",
		},
	} {
		s, h := ja3Of(t, tc.rec)
		if s != tc.str || h != tc.hash {
			t.Errorf("%s:\n got %s %s\nwant %s %s", tc.name, s, h, tc.str, tc.hash)
		}
	}
}

// ClientHellos captured from real clients on this project's dev machine,
// with the JA3 strings and hashes Wireshark 4.2.2 computed for them
// (tshark -T fields -e tls.handshake.ja3_full -e tls.handshake.ja3).
func TestJA3Captures(t *testing.T) {
	const ciphers13 = "4866-4867-4865-49196-49200-159-52393-52392-52394-49195-49199-158-49188-49192-107-49187-49191-103-49162-49172-57-49161-49171-51-157-156-61-60-53-47-255"
	const groups = "29-23-30-25-24-256-257-258-259-260"
	for _, tc := range []struct{ file, str, hash string }{
		{"curl.bin", "771," + ciphers13 + ",0-11-10-16-22-23-49-13-43-45-51-21," + groups + ",0-1-2",
			"0149f47eabf9a20d0893e2a44e5a6323"},
		{"openssl.bin", "771," + ciphers13 + ",0-11-10-35-22-23-13-43-45-51," + groups + ",0-1-2",
			"a3afc2c46ba4a7d7fbe1cfb7a3031c2f"},
		{"python.bin", "771," + ciphers13 + ",0-11-10-35-22-23-13-43-45-51-21," + groups + ",0-1-2",
			"d39e1be3241d516b1f714bd47c2bc968"},
		{"tls12.bin", "771,49196-49200-159-52393-52392-52394-49195-49199-158-49188-49192-107-49187-49191-103-49162-49172-57-49161-49171-51-157-156-61-60-53-47-255,0-11-10-35-22-23-13,29-23-30-25-24,0-1-2",
			"871a754af286dfb70c1b53c6887c62e0"},
	} {
		rec, err := os.ReadFile(filepath.Join("testdata", "ja3", tc.file))
		if err != nil {
			t.Fatal(err)
		}
		s, h := ja3Of(t, rec)
		if s != tc.str || h != tc.hash {
			t.Errorf("%s:\n got %s %s\nwant %s %s", tc.file, s, h, tc.str, tc.hash)
		}
		if md5hex(tc.str) != tc.hash {
			t.Errorf("%s: fixture hash is not md5 of its string", tc.file)
		}

		// Split across segments and reassembled: same fingerprint.
		p := streamed(40000, 443, string(rec[len(rec)/2:]), packet.AppTLS, rec)
		if p.AppFields["ja3_hash"] != tc.hash {
			t.Errorf("%s reassembled: %v", tc.file, p.AppFields)
		}
		// The first half alone is truncated: no fingerprint.
		p = parse(tcp4(40000, 443, string(rec[:len(rec)/2])))
		if _, ok := p.AppFields["ja3_hash"]; ok {
			t.Errorf("%s truncated: ja3 set: %v", tc.file, p.AppFields)
		}
	}
}

// Every GREASE value (RFC 8701) in the cipher, extension and group lists
// is left out, wherever it appears; values that only look similar stay.
func TestJA3GREASE(t *testing.T) {
	want := "771,4865-49195,0-10-11,29-23,0"
	plain := hello(771, []uint16{4865, 49195}, sniExt("example.com"), groupsExt(29, 23), pointsExt(0))
	if s, _ := ja3Of(t, plain); s != want {
		t.Fatalf("plain: %s", s)
	}
	for i := range 16 {
		g := uint16(i)<<12 | uint16(i)<<4 | 0x0a0a
		rec := hello(771, []uint16{g, 4865, 49195, g},
			ext(g, nil), sniExt("example.com"), groupsExt(g, 29, 23), ext(g^0x1010, []byte{0}), pointsExt(0))
		s, h := ja3Of(t, rec)
		if s != want || h != md5hex(want) {
			t.Errorf("GREASE %#04x: %s %s", g, s, h)
		}
	}
	// Near misses are real values.
	for _, v := range []uint16{0x0a0b, 0x0b0a, 0x1a0a, 0x0a1a, 0xfafb, 0x0000, 0xabab} {
		rec := hello(771, []uint16{v}, groupsExt(v))
		s, _ := ja3Of(t, rec)
		n := strconv.Itoa(int(v))
		if want := "771," + n + ",10," + n + ","; s != want {
			t.Errorf("%#04x: got %s, want %s", v, s, want)
		}
	}
}

// A ClientHello with an overrunning extension gets no fingerprint (a
// partial one would be a different, wrong JA3).
func TestJA3Malformed(t *testing.T) {
	rec := hello(771, []uint16{4865}, sniExt("example.com"), groupsExt(29))
	// Grow the last extension's declared length past the end.
	rec[len(rec)-6] = 0xff
	p := parse(tcp4(40000, 443, string(rec)))
	if _, ok := p.AppFields["ja3_hash"]; ok {
		t.Errorf("overrun: %v", p.AppFields)
	}
	if p.AppFields["sni"] != "example.com" {
		t.Errorf("SNI before the bad extension lost: %v", p.AppFields)
	}
}

func FuzzJA3(f *testing.F) {
	for _, name := range []string{"curl.bin", "openssl.bin", "python.bin", "tls12.bin"} {
		rec, err := os.ReadFile(filepath.Join("testdata", "ja3", name))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(rec)
	}
	f.Add(hello(769, []uint16{4, 0x0a0a}, ext(0x1a1a, nil), groupsExt(0x2a2a, 23), pointsExt(0, 1)))
	f.Fuzz(func(t *testing.T, rec []byte) {
		p := parse(tcp4(40000, 443, string(rec)))
		s, ok := p.AppFields["ja3"]
		if !ok {
			if _, ok := p.AppFields["ja3_hash"]; ok {
				t.Fatal("ja3_hash without ja3")
			}
			return
		}
		if p.AppFields["ja3_hash"] != md5hex(s) {
			t.Fatalf("hash %q is not md5(%q)", p.AppFields["ja3_hash"], s)
		}
		fields := strings.Split(s, ",")
		if len(fields) != 5 || fields[0] == "" {
			t.Fatalf("ja3 %q: want 5 fields and a version", s)
		}
		for _, f := range fields {
			if f == "" {
				continue
			}
			for _, tok := range strings.Split(f, "-") {
				v, err := strconv.ParseUint(tok, 10, 16)
				if err != nil {
					t.Fatalf("ja3 %q: bad number %q", s, tok)
				}
				if f != fields[0] && f != fields[4] && v>>8 == v&0xff && v&0x0f == 0x0a {
					t.Fatalf("ja3 %q: GREASE %d kept", s, v)
				}
			}
		}
	})
}
