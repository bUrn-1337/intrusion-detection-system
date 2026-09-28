package stream

// TCP sequence numbers wrap at 2^32, so they are compared with RFC 1982
// serial number arithmetic (SERIAL_BITS = 32): a is before b when b lies
// less than 2^31 ahead of a, going round the wrap if needed. Two numbers
// exactly 2^31 apart are undefined in RFC 1982; here neither is before
// the other, so seqLT(a, b) and seqLT(b, a) are never both true.

// seqHalf is the one distance at which serial comparison is undefined.
const seqHalf = 1 << 31

// seqLT reports whether a comes before b.
func seqLT(a, b uint32) bool {
	d := b - a
	return d != 0 && d < seqHalf
}

// seqLEQ reports whether a comes before b or equals it.
func seqLEQ(a, b uint32) bool { return a == b || seqLT(a, b) }

// seqMax returns whichever of a and b comes later, or a when neither does.
func seqMax(a, b uint32) uint32 {
	if seqLT(a, b) {
		return b
	}
	return a
}

// seqMin returns whichever of a and b comes first, or a when neither does.
func seqMin(a, b uint32) uint32 {
	if seqLT(b, a) {
		return b
	}
	return a
}
