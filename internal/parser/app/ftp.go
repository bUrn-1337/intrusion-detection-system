package app

import (
	"bytes"
	"strings"

	"github.com/bUrn-1337/intrusion-detection-system/internal/packet"
)

// ftpRedacted replaces the argument of commands that carry a password.
const ftpRedacted = "<redacted>"

// parseFTP decodes the first line of an FTP control-channel segment: a
// reply ("230 Logged in", or "230-" opening a multi-line reply, whose code
// is the one recorded) or a command ("USER alice"). Commands are
// case-insensitive and stored uppercased. A line need not be CRLF
// terminated in this segment. It returns nil for anything else, such as
// the middle lines of a multi-line reply or TLS after AUTH TLS.
func parseFTP(b []byte) *result {
	line := b
	if i := bytes.IndexAny(b, "\r\n"); i >= 0 {
		line = b[:i]
	}

	if len(b) >= 3 && '1' <= b[0] && b[0] <= '5' && isDigit(b[1]) && isDigit(b[2]) &&
		(len(b) == 3 || b[3] == ' ' || b[3] == '-' || b[3] == '\r' || b[3] == '\n') {
		r := &result{proto: packet.AppFTP}
		r.set("response_code", string(b[:3]))
		return r
	}

	cmd, arg, hasArg := bytes.Cut(line, []byte(" "))
	if len(cmd) < 3 || len(cmd) > 4 || !allLetters(cmd) {
		return nil
	}
	r := &result{proto: packet.AppFTP}
	command := strings.ToUpper(string(cmd))
	r.set("command", command)
	if hasArg {
		if command == "PASS" {
			r.set("argument", ftpRedacted)
		} else {
			r.set("argument", string(arg))
		}
	}
	return r
}

func allLetters(b []byte) bool {
	for _, c := range b {
		if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z') {
			return false
		}
	}
	return true
}
