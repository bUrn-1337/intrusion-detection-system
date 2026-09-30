package rules

import (
	"encoding/hex"
	"net/netip"
	"strconv"
	"time"

	"github.com/bUrn-1337/intrusion-detection-system/internal/entropy"
)

// icmp_tunnel thresholds. Tunnel tools (ptunnel, icmpsh, hans) put their
// data in echo payloads, so the payloads vary in size with the traffic or
// look random because the data is compressed or encrypted. Ping sends one
// size, and its payload is a fixed pattern (see standardEcho).
const (
	// tunnelMinSizes is how many distinct payload sizes among the counted
	// packets make them a tunnel.
	tunnelMinSizes = 3
	// tunnelMinEntropy is the mean Shannon entropy, in bits per byte,
	// above which the counted payloads look like compressed or encrypted
	// data. n bytes have at most log2(n) bits, so only payloads over 64
	// bytes can reach it.
	tunnelMinEntropy = 6
	// tunnelSampleLen is how many payload bytes the alert shows in hex.
	tunnelSampleLen = 16
)

// icmpTunnel is the detect:icmp_tunnel detector for one rule. Per (client,
// server) pair, where the client sends the echo requests and the server
// the replies, it keeps the size and entropy of the last count echo
// payloads in either direction that match no standard ping pattern. It
// fires when count of them fall within seconds and they either come in at
// least tunnelMinSizes sizes or average more than tunnelMinEntropy bits.
type icmpTunnel struct {
	rule *Rule
	win  *windowCounter[addrPair] // tag: payload size, val: entropy
}

func newICMPTunnel(r *Rule, max int, stat *tableStat) *icmpTunnel {
	return &icmpTunnel{rule: r, win: newWindowCounter[addrPair](r.detect.count, r.detect.span(), max, stat)}
}

// observe counts one echo payload. request says whether it is an echo
// request (from client to server) or a reply (from server to client).
func (d *icmpTunnel) observe(payload []byte, src, dst netip.Addr, request bool, t time.Time) (addrPair, func() map[string]string, bool) {
	pair := addrPair{src: src, dst: dst}
	if !request {
		pair = addrPair{src: dst, dst: src}
	}
	if standardEcho(payload) != "" {
		return pair, nil, false
	}
	size := min(len(payload), 0xffff)
	ent, full := d.win.addVal(pair, t, uint16(size), float32(entropy.Shannon(payload)))
	if !full {
		return pair, nil, false
	}
	sizes, mean := ent.distinctTags(), ent.meanVal()
	if sizes < tunnelMinSizes && mean <= tunnelMinEntropy {
		return pair, nil, false
	}
	r := d.rule
	sample := hex.EncodeToString(payload[:min(len(payload), tunnelSampleLen)])
	details := func() map[string]string {
		return map[string]string{
			"detector":         DetectICMPTunnel,
			"client":           pair.src.String(),
			"server":           pair.dst.String(),
			"payloads":         strconv.Itoa(ent.size()),
			"distinct_sizes":   strconv.Itoa(sizes),
			"avg_entropy":      strconv.FormatFloat(mean, 'f', 2, 64),
			"payload_hex":      sample,
			"payload_len":      strconv.Itoa(len(payload)),
			"seconds":          strconv.Itoa(r.detect.seconds),
			"window":           ent.newest().Sub(ent.oldest()).Round(time.Millisecond).String(),
			"min_sizes":        strconv.Itoa(tunnelMinSizes),
			"min_entropy_bits": strconv.Itoa(tunnelMinEntropy),
		}
	}
	return pair, details, true
}

func (d *icmpTunnel) clear() { d.win.clear() }
