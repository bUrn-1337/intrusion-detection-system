package entropy

import (
	"math"
	"math/rand/v2"
	"testing"
)

func TestShannon(t *testing.T) {
	all := make([]byte, 256)
	for i := range all {
		all[i] = byte(i)
	}
	tests := []struct {
		in   string
		want float64
	}{
		{"", 0},
		{"aaaaaaaa", 0},
		{"ab", 1},
		{"abcd", 2},
		{"abcdefghijklmnop", 4},
		{"aab", -(2.0/3*math.Log2(2.0/3) + 1.0/3*math.Log2(1.0/3))},
		{string(all), 8},
	}
	for _, tt := range tests {
		if got := Shannon([]byte(tt.in)); math.Abs(got-tt.want) > 1e-9 {
			t.Errorf("Shannon(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

// TestShannonBound checks the documented log2(n) cap and that random data
// of a typical tunnel packet size scores above 6.
func TestShannonBound(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	for _, n := range []int{1, 16, 64, 65, 200, 1000} {
		b := make([]byte, n)
		for i := range b {
			b[i] = byte(r.IntN(256))
		}
		h := Shannon(b)
		if h > math.Log2(float64(n))+1e-9 {
			t.Errorf("Shannon of %d random bytes = %v, above log2(n)", n, h)
		}
		if n >= 200 && h <= 6 {
			t.Errorf("Shannon of %d random bytes = %v, want > 6", n, h)
		}
	}
}
