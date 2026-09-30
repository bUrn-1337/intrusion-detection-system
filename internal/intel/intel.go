// Package intel loads threat-intelligence feeds: lists of IP addresses and
// networks, domain names and JA3 fingerprints, one entry per line.
//
// # File format
//
// Blank lines are skipped and '#' starts a comment anywhere on a line.
// Each remaining line is one entry:
//
//   - ip: an IPv4 or IPv6 address or CIDR prefix (203.0.113.7,
//     198.51.100.0/24, 2001:db8::/32). Host bits after the prefix length
//     are ignored. Addresses that are never a public Internet host are
//     rejected: private (RFC 1918, IPv6 ULA fc00::/7), loopback,
//     link-local, CGNAT (100.64.0.0/10), multicast, unspecified,
//     0.0.0.0/8 and the limited broadcast address. A prefix that overlaps
//     any of them is rejected too, so a typo like 10.0.0.0/7 cannot turn
//     every internal address into a match.
//   - domain: a DNS name (evil.example). It matches the name and every
//     name below it (a.b.evil.example), never a name that merely ends
//     with the same text (notevil.example). Names are case-insensitive and
//     a trailing dot is ignored. A name must have at least two labels and
//     at least one letter, and labels hold only letters, digits, '-' and
//     '_' (write internationalized names in their xn-- form).
//   - ja3: a JA3 MD5 hash, 32 hex digits, optionally followed by
//     ",label" (a malware family, say). The label is trimmed, cut to 64
//     bytes, and any character other than printable ASCII, or one of
//     ';', '"' and '\', becomes '_'.
//
// A rejected line is reported with its file and line number, and loading
// goes on with the next line. Duplicate entries count once.
package intel

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"slices"
	"strings"
	"time"
)

// Type is the kind of entry a feed holds.
type Type uint8

const (
	IP Type = iota + 1
	Domain
	JA3
)

var typeNames = [...]string{IP: "ip", Domain: "domain", JA3: "ja3"}

func (t Type) String() string {
	if int(t) < len(typeNames) && typeNames[t] != "" {
		return typeNames[t]
	}
	return fmt.Sprintf("Type(%d)", uint8(t))
}

// ParseType parses "ip", "domain" or "ja3".
func ParseType(s string) (Type, bool) {
	for t, name := range typeNames {
		if name != "" && name == s {
			return Type(t), true
		}
	}
	return 0, false
}

// Limits on one feed file.
const (
	// MaxEntries bounds the entries of one feed; later lines are
	// reported and ignored. The largest public feeds hold a few hundred
	// thousand entries.
	MaxEntries = 2_000_000
	// MaxLineLen bounds a line; a longer one is rejected.
	MaxLineLen = 4096
	// MaxProblems bounds the problems kept per feed; Rejected counts them
	// all.
	MaxProblems = 20
	// maxLabel bounds a JA3 label.
	maxLabel = 64
)

// DefaultMaxAge is the age after which a feed counts as stale.
const DefaultMaxAge = 7 * 24 * time.Hour

// Problem is one rejected line of a feed file.
type Problem struct {
	File   string
	Line   int
	Reason string
}

func (p Problem) String() string { return fmt.Sprintf("%s:%d: %s", p.File, p.Line, p.Reason) }

// Feed is one loaded feed. It is immutable after loading and may be
// shared between goroutines.
type Feed struct {
	Name    string
	Type    Type
	Path    string
	ModTime time.Time     // the file's modification time
	MaxAge  time.Duration // older than this is stale; 0 never is
	// Entries is the number of distinct entries loaded. Rejected is the
	// number of lines rejected; Problems holds the first MaxProblems.
	Entries  int
	Rejected int
	Problems []Problem

	ips     ipSet
	domains map[string]struct{} // reversed labels: "example.com" is "com.example"
	ja3     map[string]string   // hash -> label
}

// Load reads the feed file at path. Only an I/O error fails it; bad lines
// are counted in Rejected and listed in Problems.
func Load(name string, typ Type, path string) (*Feed, error) {
	// Only regular files: opening a FIFO blocks until a writer comes, and
	// /dev/zero or /dev/stdin would never end. Checked before the open,
	// and again on the open file in case the path changed in between.
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if err := regular(path, st); err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if st, err = f.Stat(); err != nil {
		return nil, err
	}
	if err := regular(path, st); err != nil {
		return nil, err
	}
	feed, err := Parse(f, name, typ, path)
	if err != nil {
		return nil, err
	}
	feed.ModTime = st.ModTime()
	return feed, nil
}

func regular(path string, st os.FileInfo) error {
	switch {
	case st.IsDir():
		return fmt.Errorf("%s is a directory", path)
	case !st.Mode().IsRegular():
		return fmt.Errorf("%s is not a regular file (%s)", path, st.Mode().Type())
	}
	return nil
}

// Parse reads a feed from r. path is used in problems. ModTime is left
// zero.
func Parse(r io.Reader, name string, typ Type, path string) (*Feed, error) {
	if typ < IP || typ > JA3 {
		return nil, fmt.Errorf("unknown feed type %v", typ)
	}
	f := &Feed{Name: name, Type: typ, Path: path, MaxAge: DefaultMaxAge}
	var b ipBuilder
	switch typ {
	case Domain:
		f.domains = make(map[string]struct{})
	case JA3:
		f.ja3 = make(map[string]string)
	}
	reject := func(line int, format string, args ...any) {
		f.Rejected++
		if len(f.Problems) < MaxProblems {
			f.Problems = append(f.Problems, Problem{path, line, fmt.Sprintf(format, args...)})
		}
	}
	br := bufio.NewReaderSize(r, 64<<10)
	for n := 1; ; n++ {
		line, long, err := readLine(br)
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
		eof := err != nil
		if n == 1 {
			line = bytes.TrimPrefix(line, []byte("\uFEFF"))
		}
		if i := bytes.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		line = bytes.TrimSpace(line)
		var entries int
		switch {
		case long:
			reject(n, "line longer than %d bytes", MaxLineLen)
		case len(line) == 0:
		case typ == IP:
			p, reason := parseIPEntry(string(line))
			if reason != "" {
				reject(n, "%s", reason)
				break
			}
			b.add(p)
			entries = b.distinct
		case typ == Domain:
			key, reason := domainKey(string(line))
			if reason != "" {
				reject(n, "%s", reason)
				break
			}
			f.domains[key] = struct{}{}
			entries = len(f.domains)
		case typ == JA3:
			hash, label, reason := parseJA3Entry(string(line))
			if reason != "" {
				reject(n, "%s", reason)
				break
			}
			if _, dup := f.ja3[hash]; !dup {
				f.ja3[hash] = label
			}
			entries = len(f.ja3)
		}
		if eof {
			break
		}
		if entries >= MaxEntries {
			if rest := countRest(br); rest > 0 {
				reject(n, "feed reached %d entries; the %d lines after this one are ignored", MaxEntries, rest)
				f.Rejected += rest - 1
			}
			break
		}
	}
	switch typ {
	case IP:
		f.ips = b.build()
		f.Entries = b.distinct
	case Domain:
		f.Entries = len(f.domains)
	case JA3:
		f.Entries = len(f.ja3)
	}
	return f, nil
}

// readLine returns the next line without its end of line. long is true
// when the line is longer than MaxLineLen; its rest is then skipped.
func readLine(br *bufio.Reader) (line []byte, long bool, err error) {
	var buf []byte
	for {
		chunk, isPrefix, err := br.ReadLine()
		if err != nil && len(chunk) == 0 && (len(buf) > 0 || long) {
			err = nil // the line ended at EOF; report EOF on the next call
		}
		if len(buf)+len(chunk) > MaxLineLen {
			long = true
		} else {
			buf = append(buf, chunk...)
		}
		if err != nil || !isPrefix {
			if long {
				buf = nil
			}
			return buf, long, err
		}
	}
}

// countRest counts the non-empty, non-comment lines left in br.
func countRest(br *bufio.Reader) int {
	n := 0
	for {
		line, long, err := readLine(br)
		if i := bytes.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		if long || len(bytes.TrimSpace(line)) > 0 {
			n++
		}
		if err != nil {
			return n
		}
	}
}

// Age returns how old the feed file is at now.
func (f *Feed) Age(now time.Time) time.Duration {
	if f.ModTime.IsZero() {
		return 0
	}
	return now.Sub(f.ModTime)
}

// Stale reports whether the feed is older than its MaxAge at now.
func (f *Feed) Stale(now time.Time) bool {
	return f.MaxAge > 0 && f.Age(now) > f.MaxAge
}

// ContainsIP reports whether a is in an ip feed. An IPv4-mapped IPv6
// address is looked up as IPv4.
func (f *Feed) ContainsIP(a netip.Addr) bool {
	return f != nil && f.ips.contains(a)
}

// MatchDomain reports whether name, or a name it is below, is in a domain
// feed, and returns the feed entry that matched (lowercase, without a
// trailing dot). It does not allocate unless it matches.
func (f *Feed) MatchDomain(name string) (string, bool) {
	if f == nil || len(f.domains) == 0 {
		return "", false
	}
	return matchDomain(f.domains, name)
}

// LookupJA3 returns the label of a JA3 hash in a ja3 feed ("" when the
// entry has none) and whether the hash is in it. The hash may be in
// either case.
func (f *Feed) LookupJA3(hash string) (string, bool) {
	if f == nil || len(hash) != 32 {
		return "", false
	}
	label, ok := f.ja3[hash]
	if !ok && hasUpper(hash) {
		label, ok = f.ja3[strings.ToLower(hash)]
	}
	return label, ok
}

func hasUpper(s string) bool {
	for i := 0; i < len(s); i++ {
		if 'A' <= s[i] && s[i] <= 'Z' {
			return true
		}
	}
	return false
}

// ---- ip ----

// reserved lists the ranges an ip feed entry must not overlap, with the
// reason given when one does.
var reserved = []struct {
	p    netip.Prefix
	what string
}{
	{netip.MustParsePrefix("0.0.0.0/8"), "\"this network\" (0.0.0.0/8, includes the unspecified address)"},
	{netip.MustParsePrefix("10.0.0.0/8"), "private (RFC 1918, 10.0.0.0/8)"},
	{netip.MustParsePrefix("100.64.0.0/10"), "carrier-grade NAT (100.64.0.0/10)"},
	{netip.MustParsePrefix("127.0.0.0/8"), "loopback (127.0.0.0/8)"},
	{netip.MustParsePrefix("169.254.0.0/16"), "link-local (169.254.0.0/16)"},
	{netip.MustParsePrefix("172.16.0.0/12"), "private (RFC 1918, 172.16.0.0/12)"},
	{netip.MustParsePrefix("192.168.0.0/16"), "private (RFC 1918, 192.168.0.0/16)"},
	{netip.MustParsePrefix("224.0.0.0/4"), "multicast (224.0.0.0/4)"},
	{netip.MustParsePrefix("255.255.255.255/32"), "the limited broadcast address"},
	{netip.MustParsePrefix("::/128"), "the unspecified address (::)"},
	{netip.MustParsePrefix("::1/128"), "loopback (::1)"},
	{netip.MustParsePrefix("fc00::/7"), "private (unique local, fc00::/7)"},
	{netip.MustParsePrefix("fe80::/10"), "link-local (fe80::/10)"},
	{netip.MustParsePrefix("ff00::/8"), "multicast (ff00::/8)"},
}

// parseIPEntry parses an address or prefix and checks it is public.
func parseIPEntry(s string) (netip.Prefix, string) {
	var p netip.Prefix
	if strings.Contains(s, "/") {
		var err error
		if p, err = netip.ParsePrefix(s); err != nil {
			return p, fmt.Sprintf("%q is not an IP address or CIDR prefix", s)
		}
		p = p.Masked()
	} else {
		a, err := netip.ParseAddr(s)
		if err != nil || a.Zone() != "" {
			return p, fmt.Sprintf("%q is not an IP address or CIDR prefix", s)
		}
		p = netip.PrefixFrom(a, a.BitLen())
	}
	if p.Addr().Is4In6() {
		return p, fmt.Sprintf("%s is an IPv4-mapped IPv6 address: write the IPv4 form", s)
	}
	for _, r := range reserved {
		if p.Overlaps(r.p) {
			if p.Bits() < r.p.Bits() {
				return p, fmt.Sprintf("%s includes a range that is %s", p, r.what)
			}
			if p.IsSingleIP() {
				return p, fmt.Sprintf("%s is %s", p.Addr(), r.what)
			}
			return p, fmt.Sprintf("%s is %s", p, r.what)
		}
	}
	return p, ""
}

type range4 struct{ lo, hi uint32 }

type range6 struct{ lo, hi [16]byte }

// ipSet is a set of addresses as sorted, disjoint, non-adjacent ranges,
// searched by binary search.
type ipSet struct {
	v4 []range4
	v6 []range6
}

type ipBuilder struct {
	v4       []range4
	v6       []range6
	seen     map[netip.Prefix]struct{}
	distinct int
}

func (b *ipBuilder) add(p netip.Prefix) {
	if b.seen == nil {
		b.seen = make(map[netip.Prefix]struct{})
	}
	if _, dup := b.seen[p]; dup {
		return
	}
	b.seen[p] = struct{}{}
	b.distinct++
	lo := p.Addr()
	if lo.Is4() {
		l := be32(lo.As4())
		host := uint32(1)<<(32-p.Bits()) - 1
		if p.Bits() == 0 {
			host = ^uint32(0)
		}
		b.v4 = append(b.v4, range4{l, l | host})
		return
	}
	l := lo.As16()
	h := l
	for i := p.Bits(); i < 128; i++ {
		h[i/8] |= 0x80 >> (i % 8)
	}
	b.v6 = append(b.v6, range6{l, h})
}

func (b *ipBuilder) build() ipSet {
	slices.SortFunc(b.v4, func(x, y range4) int {
		switch {
		case x.lo < y.lo:
			return -1
		case x.lo > y.lo:
			return 1
		}
		return 0
	})
	var s ipSet
	for _, r := range b.v4 {
		if n := len(s.v4); n > 0 && (r.lo <= s.v4[n-1].hi || s.v4[n-1].hi != ^uint32(0) && r.lo == s.v4[n-1].hi+1) {
			s.v4[n-1].hi = max(s.v4[n-1].hi, r.hi)
			continue
		}
		s.v4 = append(s.v4, r)
	}
	slices.SortFunc(b.v6, func(x, y range6) int { return bytes.Compare(x.lo[:], y.lo[:]) })
	for _, r := range b.v6 {
		if n := len(s.v6); n > 0 && bytes.Compare(r.lo[:], s.v6[n-1].hi[:]) <= 0 {
			if bytes.Compare(r.hi[:], s.v6[n-1].hi[:]) > 0 {
				s.v6[n-1].hi = r.hi
			}
			continue
		}
		s.v6 = append(s.v6, r)
	}
	s.v4, s.v6 = slices.Clip(s.v4), slices.Clip(s.v6)
	b.v4, b.v6, b.seen = nil, nil, nil
	return s
}

func be32(a [4]byte) uint32 {
	return uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
}

func (s *ipSet) contains(a netip.Addr) bool {
	if !a.IsValid() {
		return false
	}
	a = a.Unmap()
	if a.Is4() {
		x := be32(a.As4())
		// The first range starting after x; the one before it is the only
		// candidate.
		i, _ := slices.BinarySearchFunc(s.v4, x, func(r range4, x uint32) int {
			if r.lo <= x {
				return -1
			}
			return 1
		})
		return i > 0 && x <= s.v4[i-1].hi
	}
	x := a.As16()
	i, _ := slices.BinarySearchFunc(s.v6, x, func(r range6, x [16]byte) int {
		if bytes.Compare(r.lo[:], x[:]) <= 0 {
			return -1
		}
		return 1
	})
	return i > 0 && bytes.Compare(x[:], s.v6[i-1].hi[:]) <= 0
}

// ---- domain ----

// domainKey checks a domain entry and returns its map key: the labels in
// reverse order, lowercase ("www.example.com" is "com.example.www").
func domainKey(s string) (string, string) {
	name := strings.TrimSuffix(strings.ToLower(s), ".")
	name = strings.TrimPrefix(name, "*.") // a wildcard means the same thing
	if _, err := netip.ParseAddr(name); err == nil {
		return "", fmt.Sprintf("%q is an IP address: put it in an ip feed", s)
	}
	if reason := checkDomain(name); reason != "" {
		return "", fmt.Sprintf("%q is not a domain name: %s", s, reason)
	}
	labels := strings.Split(name, ".")
	slices.Reverse(labels)
	return strings.Join(labels, "."), ""
}

func checkDomain(name string) string {
	switch {
	case name == "":
		return "empty"
	case len(name) > 253:
		return "longer than 253 bytes"
	}
	letter := false
	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		return "a single label would match a whole top-level domain"
	}
	for _, l := range labels {
		if l == "" {
			return "empty label"
		}
		if len(l) > 63 {
			return "label longer than 63 bytes"
		}
		for i := 0; i < len(l); i++ {
			switch c := l[i]; {
			case 'a' <= c && c <= 'z':
				letter = true
			case '0' <= c && c <= '9', c == '-', c == '_':
			default:
				return fmt.Sprintf("character %q not allowed (letters, digits, '-' and '_' only)", c)
			}
		}
	}
	if !letter {
		return "no letter"
	}
	return ""
}

// matchDomain looks name and each name it is below up in m, keyed by
// reversed labels, from the top-level domain down, and returns the
// shortest entry that matches.
func matchDomain(m map[string]struct{}, name string) (string, bool) {
	name = strings.TrimSuffix(name, ".")
	if name == "" || len(name) > 253 {
		return "", false
	}
	var arr [256]byte
	key := arr[:0]
	end := len(name)
	for end > 0 {
		start := strings.LastIndexByte(name[:end], '.') + 1
		if len(key) > 0 {
			key = append(key, '.')
		}
		for i := start; i < end; i++ {
			c := name[i]
			if 'A' <= c && c <= 'Z' {
				c += 'a' - 'A'
			}
			key = append(key, c)
		}
		if _, ok := m[string(key)]; ok {
			return strings.ToLower(name[start:]), true
		}
		end = start - 1
	}
	return "", false
}

// ---- ja3 ----

func parseJA3Entry(s string) (hash, label, reason string) {
	hash, label, _ = strings.Cut(s, ",")
	hash = strings.ToLower(strings.TrimSpace(hash))
	if len(hash) != 32 || strings.Trim(hash, "0123456789abcdef") != "" {
		return "", "", fmt.Sprintf("%q is not a JA3 hash (32 hex digits)", strings.TrimSpace(s[:min(len(s), 40)]))
	}
	return hash, sanitizeLabel(label), ""
}

func sanitizeLabel(s string) string {
	s = strings.TrimSpace(s)
	b := []byte(s[:min(len(s), maxLabel)])
	for i, c := range b {
		if c < 0x20 || c > 0x7e || c == ';' || c == '"' || c == '\\' {
			b[i] = '_'
		}
	}
	return strings.TrimSpace(string(b))
}
