package app

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"strconv"
)

// TLS extensions JA3 reads the lists of.
const (
	tlsExtSupportedGroups = 10 // "elliptic_curves" before RFC 8422
	tlsExtECPointFormats  = 11
)

// ja3 builds a JA3 fingerprint (github.com/salesforce/ja3) of a
// ClientHello: the fields
//
//	TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
//
// as decimal numbers, each list joined with '-' and the fields with ','
// (an absent list is empty), and the MD5 of that string. TLSVersion is
// the ClientHello's legacy_version (771 for TLS 1.2 and 1.3), not the
// record version. GREASE values (RFC 8701) are left out of every list, so
// a client that sends random GREASE values keeps one fingerprint.
type ja3 struct {
	buf    []byte // version,ciphers,extensions
	curves []byte
	points []byte
	nExt   int
}

// isGREASE reports whether v is one of the 16 reserved GREASE values
// 0x0a0a, 0x1a1a, ..., 0xfafa: both bytes equal, low nibble 0xa.
func isGREASE(v uint16) bool {
	return v>>8 == v&0xff && v&0x0f == 0x0a
}

func (j *ja3) init(version uint16, ciphers []byte) {
	j.buf = strconv.AppendUint(make([]byte, 0, 256), uint64(version), 10)
	j.buf = append(j.buf, ',')
	j.buf = appendList16(j.buf, ciphers)
	j.buf = append(j.buf, ',')
}

// extension adds one extension (in ClientHello order) and reads the
// curve and point format lists from their extensions.
func (j *ja3) extension(typ uint16, data []byte) {
	if isGREASE(typ) {
		return
	}
	if j.nExt > 0 {
		j.buf = append(j.buf, '-')
	}
	j.nExt++
	j.buf = strconv.AppendUint(j.buf, uint64(typ), 10)
	switch typ {
	case tlsExtSupportedGroups:
		if len(data) >= 2 {
			n := min(int(binary.BigEndian.Uint16(data)), len(data)-2)
			j.curves = appendList16(j.curves[:0], data[2:2+n])
		}
	case tlsExtECPointFormats:
		if len(data) >= 1 {
			n := min(int(data[0]), len(data)-1)
			j.points = j.points[:0]
			for i, b := range data[1 : 1+n] {
				if i > 0 {
					j.points = append(j.points, '-')
				}
				j.points = strconv.AppendUint(j.points, uint64(b), 10)
			}
		}
	}
}

// commit sets the ja3 and ja3_hash fields.
func (j *ja3) commit(r *result) {
	s := append(j.buf, ',')
	s = append(s, j.curves...)
	s = append(s, ',')
	s = append(s, j.points...)
	sum := md5.Sum(s)
	r.set("ja3", string(s))
	r.set("ja3_hash", hex.EncodeToString(sum[:]))
}

// appendList16 appends the big-endian 16-bit values of b, GREASE values
// left out, joined with '-'. A trailing odd byte is ignored.
func appendList16(dst, b []byte) []byte {
	first := true
	for i := 0; i+1 < len(b); i += 2 {
		v := binary.BigEndian.Uint16(b[i:])
		if isGREASE(v) {
			continue
		}
		if !first {
			dst = append(dst, '-')
		}
		first = false
		dst = strconv.AppendUint(dst, uint64(v), 10)
	}
	return dst
}
