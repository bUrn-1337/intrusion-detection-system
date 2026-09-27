package rules

// Standard echo payloads, the data after the ICMP id and seq that common
// ping programs send. An echo reply carries the request's data back, so
// the same patterns apply to both.
const (
	// EchoLinux is iputils or BSD ping: data byte i is byte(i) (so it
	// counts 0x00, 0x01, ... and wraps after 0xff), except that the first
	// 8 bytes (a 32-bit struct timeval) or 16 bytes (64-bit) may be a
	// send timestamp. With the timestamp, the counting part starts at
	// 0x08 or 0x10: ping -s 56 on 64-bit Linux sends 16 timestamp bytes,
	// then 0x10 0x11 ... 0x37. Payloads shorter than a timestamp carry
	// none and count from 0x00.
	EchoLinux = "linux_bsd"
	// EchoWindows is Windows ping: "abcdefghijklmnopqrstuvw" repeated
	// (23 letters, 'a' + i%23), cut to size. The default 32 bytes are
	// "abcdefghijklmnopqrstuvwabcdefghi".
	EchoWindows = "windows"
	// EchoZero is all zero bytes, as some network devices and monitoring
	// tools send.
	EchoZero = "zero"
	// EchoEmpty is no data at all.
	EchoEmpty = "empty"
)

// echoTimestampLens are the timestamp sizes allowed before the counting
// part of a Linux or BSD payload, besides none.
var echoTimestampLens = [...]int{8, 16}

// standardEcho returns which standard pattern b is, or "" if none. The
// timestamp bytes of a Linux/BSD payload are not checked (they are a
// time, so any value), but at least one counting byte must follow them:
// a payload of exactly 8 or 16 bytes is only standard if it counts from
// 0x00. A tunnel can therefore hide up to 16 bytes per packet in a
// "timestamp"; it has to repeat the counting bytes after them.
func standardEcho(b []byte) string {
	if len(b) == 0 {
		return EchoEmpty
	}
	if isCounting(b, 0) {
		return EchoLinux
	}
	for _, ts := range echoTimestampLens {
		if len(b) > ts && isCounting(b, ts) {
			return EchoLinux
		}
	}
	if isWindowsEcho(b) {
		return EchoWindows
	}
	if isZeros(b) {
		return EchoZero
	}
	return ""
}

// isCounting reports whether b[i] == byte(i) for every i >= from.
func isCounting(b []byte, from int) bool {
	for i := from; i < len(b); i++ {
		if b[i] != byte(i) {
			return false
		}
	}
	return true
}

func isWindowsEcho(b []byte) bool {
	for i, c := range b {
		if c != 'a'+byte(i%23) {
			return false
		}
	}
	return true
}

func isZeros(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}
