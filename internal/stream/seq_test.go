package stream

import "testing"

func TestSeqLT(t *testing.T) {
	tests := []struct {
		a, b uint32
		want bool
	}{
		{0, 1, true},
		{1, 0, false},
		{5, 5, false},
		{0xFFFFFFFF, 0, true}, // across the wrap
		{0, 0xFFFFFFFF, false},
		{0xFFFFFF00, 0x100, true},
		{0x100, 0xFFFFFF00, false},
		{0, 0x7FFFFFFF, true}, // largest distance that is still "after"
		{0x7FFFFFFF, 0, false},
		{0, 0x80000000, false}, // exactly 2^31 apart: undefined, neither
		{0x80000000, 0, false},
		{0, 0x80000001, false}, // past half the space: b is behind a
		{0x80000001, 0, true},
		{0xFFFFFFFF, 0x7FFFFFFE, true},
		{0xFFFFFFFF, 0x7FFFFFFF, false}, // 2^31 apart across the wrap
	}
	for _, tc := range tests {
		if got := seqLT(tc.a, tc.b); got != tc.want {
			t.Errorf("seqLT(%#x, %#x) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestSeqLEQMaxMin(t *testing.T) {
	if !seqLEQ(7, 7) || !seqLEQ(0xFFFFFFFF, 3) || seqLEQ(3, 0xFFFFFFFF) {
		t.Error("seqLEQ wrong")
	}
	if seqLEQ(0, 0x80000000) || seqLEQ(0x80000000, 0) {
		t.Error("seqLEQ at 2^31 should be false both ways")
	}
	if got := seqMax(0xFFFFFFF0, 0x10); got != 0x10 {
		t.Errorf("seqMax across wrap = %#x", got)
	}
	if got := seqMin(0xFFFFFFF0, 0x10); got != 0xFFFFFFF0 {
		t.Errorf("seqMin across wrap = %#x", got)
	}
	if got := seqMax(0x10, 0xFFFFFFF0); got != 0x10 {
		t.Errorf("seqMax reversed = %#x", got)
	}
	if got := seqMax(0, 0x80000000); got != 0 {
		t.Errorf("seqMax undefined pair = %#x, want first", got)
	}
}

// Every pair is ordered one way at most, and exactly one way unless equal
// or 2^31 apart.
func TestSeqLTAntisymmetric(t *testing.T) {
	for _, a := range []uint32{0, 1, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFE, 0xFFFFFFFF, 12345} {
		for _, d := range []uint32{0, 1, 2, 0x7FFFFFFE, 0x7FFFFFFF, 0x80000000, 0x80000001, 0xFFFFFFFF} {
			b := a + d
			lt, gt := seqLT(a, b), seqLT(b, a)
			if lt && gt {
				t.Fatalf("%#x and %#x both before each other", a, b)
			}
			if want := d != 0 && d != seqHalf; (lt || gt) != want {
				t.Errorf("a=%#x d=%#x: ordered=%v, want %v", a, d, lt || gt, want)
			}
		}
	}
}
