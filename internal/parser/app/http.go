package app

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/bUrn-1337/intrusion-detection-system/internal/packet"
)

const (
	// maxHTTPHeaders and maxHTTPLine cap the header count and the length of
	// any line (request/status line or header), excluding the CRLF.
	maxHTTPHeaders = 100
	maxHTTPLine    = 8 << 10
)

var (
	crlf       = []byte("\r\n")
	crlfCRLF   = []byte("\r\n\r\n")
	h2cPreface = []byte("PRI * HTTP/2.0\r\n")
	httpSlash1 = []byte("HTTP/1.")
)

// httpMethods are the RFC 9110 methods plus PATCH (RFC 5789).
var httpMethods = []string{"GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH", "CONNECT", "TRACE"}

var (
	reasonLineTooLong      = fmt.Sprintf("line longer than %d bytes", maxHTTPLine)
	reasonTooManyHeaders   = fmt.Sprintf("more than %d headers", maxHTTPHeaders)
	reasonBadRequestLine   = "invalid request line"
	reasonBadMethod        = "invalid request method"
	reasonBadStatusLine    = "invalid status line"
	reasonBadHeaderLine    = "header line without a name"
	reasonBadContentLen    = "invalid content-length"
	reasonDoubleEncodedURI = "double percent-encoding"
)

// parseHTTP decodes an HTTP/1.x request or response head. It recognizes a
// payload that starts with a known method and a space, "HTTP/1.", or the
// HTTP/2 cleartext preface. On a port-hinted segment it also recognizes a
// request line with an unknown method ("FOO / HTTP/1.1") and reports it as
// malformed. It returns nil for anything else, such as body data.
func parseHTTP(b []byte, hinted bool) *result {
	if bytes.HasPrefix(b, h2cPreface) {
		r := &result{proto: packet.AppHTTP}
		r.set("version", "2.0")
		return r
	}

	first, terminated := firstLine(b)
	isResponse := bytes.HasPrefix(b, httpSlash1)
	method := methodPrefix(b)
	if !isResponse && method == "" && !(hinted && terminated && looksLikeRequestLine(first)) {
		return nil
	}

	r := &result{proto: packet.AppHTTP}
	r.set("request_complete", fmt.Sprint(bytes.Contains(b, crlfCRLF)))
	if len(first) > maxHTTPLine {
		r.bad(reasonLineTooLong)
		return r
	}
	var ok bool
	if isResponse {
		ok = parseStatusLine(r, first, terminated)
	} else {
		ok = parseRequestLine(r, first, terminated)
	}
	if !ok || !terminated {
		return r
	}
	parseHeaders(r, b[len(first)+len(crlf):])
	return r
}

// firstLine returns b up to the first CRLF, and whether a CRLF was found.
func firstLine(b []byte) (line []byte, terminated bool) {
	if i := bytes.Index(b, crlf); i >= 0 {
		return b[:i], true
	}
	return b, false
}

// methodPrefix returns the method if b starts with a known method and a
// space.
func methodPrefix(b []byte) string {
	for _, m := range httpMethods {
		if len(b) > len(m) && b[len(m)] == ' ' && string(b[:len(m)]) == m {
			return m
		}
	}
	return ""
}

// looksLikeRequestLine reports whether line has the shape
// "TOKEN SP TARGET SP HTTP/1.x", whatever the token.
func looksLikeRequestLine(line []byte) bool {
	parts := bytes.Split(line, []byte(" "))
	return len(parts) == 3 && len(parts[0]) > 0 && len(parts[1]) > 0 && validVersion(parts[2]) != ""
}

// validVersion returns "1.0" for "HTTP/1.0" and so on, or "" if v is not
// an HTTP version.
func validVersion(v []byte) string {
	if len(v) == 8 && bytes.HasPrefix(v, []byte("HTTP/")) && isDigit(v[5]) && v[6] == '.' && isDigit(v[7]) {
		return string(v[5:])
	}
	return ""
}

func isDigit(c byte) bool { return '0' <= c && c <= '9' }

// hasControl reports whether b contains a control character. Bytes of
// 0x80 and above are allowed (seen in real URIs).
func hasControl(b []byte) bool {
	for _, c := range b {
		if c < 0x20 || c == 0x7F {
			return true
		}
	}
	return false
}

// parseRequestLine decodes "METHOD SP URI SP VERSION". An unterminated line
// (the request continues in the next segment) is decoded as far as it
// goes. It returns false if the line is malformed.
func parseRequestLine(r *result, line []byte, terminated bool) bool {
	if hasControl(line) {
		r.bad(reasonBadRequestLine)
		return false
	}
	parts := bytes.Split(line, []byte(" "))
	if len(parts) > 3 || (terminated && len(parts) != 3) {
		r.bad(reasonBadRequestLine)
		return false
	}
	method := string(parts[0])
	if !isMethod(method) {
		r.bad(reasonBadMethod)
		return false
	}
	r.set("method", method)
	if len(parts) < 2 {
		return true // unterminated: the URI is in the next segment
	}
	if len(parts[1]) == 0 {
		if len(parts) == 3 {
			r.bad(reasonBadRequestLine)
			return false
		}
		return true // unterminated "GET "
	}
	uri := string(parts[1])
	r.set("uri", uri)
	decoded := percentDecode(uri)
	r.set("uri_decoded", decoded)
	if hidesTraversal(decoded) {
		r.flag(reasonDoubleEncodedURI)
	}
	if len(parts) == 3 {
		v := validVersion(parts[2])
		if v == "" {
			if terminated {
				r.bad(reasonBadRequestLine)
				return false
			}
			return true // the version continues in the next segment
		}
		r.set("version", v)
	}
	return true
}

func isMethod(m string) bool {
	for _, x := range httpMethods {
		if m == x {
			return true
		}
	}
	return false
}

// parseStatusLine decodes "HTTP/1.x SP 3DIGIT [SP reason]". It returns
// false if the line is malformed.
func parseStatusLine(r *result, line []byte, terminated bool) bool {
	if hasControl(line[:min(len(line), 12)]) {
		r.bad(reasonBadStatusLine)
		return false
	}
	if len(line) < 12 {
		if terminated {
			r.bad(reasonBadStatusLine)
			return false
		}
		return true // the status line continues in the next segment
	}
	v := validVersion(line[:8])
	code := line[9:12]
	if v == "" || line[8] != ' ' || !isDigit(code[0]) || !isDigit(code[1]) || !isDigit(code[2]) ||
		(len(line) > 12 && line[12] != ' ') {
		r.bad(reasonBadStatusLine)
		return false
	}
	r.set("version", v)
	r.set("status_code", string(code))
	return true
}

// parseHeaders decodes header lines up to the blank line or the end of the
// segment. A partial last line is ignored.
func parseHeaders(r *result, b []byte) {
	for count := 0; ; {
		i := bytes.Index(b, crlf)
		if i < 0 {
			if len(b) > maxHTTPLine {
				r.bad(reasonLineTooLong)
			}
			return
		}
		if i == 0 {
			return // blank line: end of headers
		}
		if i > maxHTTPLine {
			r.bad(reasonLineTooLong)
			return
		}
		if count++; count > maxHTTPHeaders {
			r.bad(reasonTooManyHeaders)
			return
		}
		line := b[:i]
		b = b[i+len(crlf):]
		if line[0] == ' ' || line[0] == '\t' {
			continue // obsolete line folding
		}
		colon := bytes.IndexByte(line, ':')
		if colon <= 0 {
			r.bad(reasonBadHeaderLine)
			return
		}
		name := strings.ToLower(string(bytes.TrimRight(line[:colon], " \t")))
		value := string(bytes.Trim(line[colon+1:], " \t"))
		switch name {
		case "host":
			setOnce(r, "host", value)
		case "user-agent":
			setOnce(r, "user_agent", value)
		case "content-type":
			setOnce(r, "content_type", value)
		case "content-length":
			if !allDigits(value) {
				r.bad(reasonBadContentLen)
				return
			}
			setOnce(r, "content_length", value)
		case "authorization":
			// Never store the credentials, only that Basic auth was used.
			scheme, _, _ := strings.Cut(value, " ")
			if strings.EqualFold(scheme, "basic") {
				r.set("auth_basic", "true")
			}
		}
	}
}

// setOnce keeps the first value of a repeated header.
func setOnce(r *result, key, value string) {
	if !r.has(key) {
		r.set(key, value)
	}
}

func allDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if !isDigit(s[i]) {
			return false
		}
	}
	return s != ""
}

// maxExtraDecodes is how many more times hidesTraversal decodes a URI
// after the first decode, so triple encoding (%25252e) is caught too.
const maxExtraDecodes = 3

// hidesTraversal reports whether decoding the once-decoded URI again
// produces a "../", "..\\" or NUL byte that was not already there: the
// sign of a double-encoded path traversal aimed at a filter that decodes
// only once. Double encoding on its own is common in benign traffic (ad
// click trackers and analytics beacons pass encoded URLs in query
// parameters, e.g. "%253A%252F%252F"), so it is not flagged.
func hidesTraversal(decoded string) bool {
	cur := decoded
	for range maxExtraDecodes {
		next := percentDecode(cur)
		if next == cur {
			return false
		}
		for _, t := range []string{"../", "..\\", "\x00"} {
			if strings.Count(next, t) > strings.Count(decoded, t) {
				return true
			}
		}
		cur = next
	}
	return false
}

// percentDecode decodes %XX escapes once. Invalid escapes are kept as is;
// "+" is not decoded (that is form encoding, not URI encoding).
func percentDecode(s string) string {
	if strings.IndexByte(s, '%') < 0 {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			if hi, ok := unhex(s[i+1]); ok {
				if lo, ok := unhex(s[i+2]); ok {
					b.WriteByte(hi<<4 | lo)
					i += 2
					continue
				}
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func unhex(c byte) (byte, bool) {
	switch {
	case '0' <= c && c <= '9':
		return c - '0', true
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10, true
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}
