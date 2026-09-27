// Package entropy measures how random a byte string looks. It is shared by
// the DNS parser (random subdomain labels) and the rule engine (ICMP
// tunnel payloads).
package entropy

import "math"

// Shannon returns the Shannon entropy of b in bits per byte: 0 for a
// repeated byte, up to 8 for uniformly random bytes. It can be at most
// log2(len(b)), because n bytes hold at most n distinct values: a
// 16-byte string scores at most 4 and one needs more than 64 bytes to
// score more than 6. Random base32 or hex text scores 4 to 5; English
// text about 4; compressed or encrypted data close to 8 once it is a few
// hundred bytes long.
func Shannon(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var counts [256]int
	for _, c := range b {
		counts[c]++
	}
	var h float64
	n := float64(len(b))
	for _, c := range counts {
		if c > 0 {
			p := float64(c) / n
			h -= p * math.Log2(p)
		}
	}
	return h
}
