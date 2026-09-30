package rules

// Attribution: every alert gets Details["attribution"], "reliable" when
// its source address (or MAC) really sent the traffic, "spoofable" when
// the alert rests on packets anyone could have sent with that source.
// Correlation (correlate.go) never names a spoofable source as an
// incident's attacker. ARCHITECTURE.md has the full table.
const (
	detailAttribution = "attribution"
	attrReliable      = "reliable"
	attrSpoofable     = "spoofable"
)

// reliable reports whether an alert of r about v is reliably attributed.
//
//   - beacon: repeated connections that were answered (TCP) or a
//     two-way exchange pattern: reliable.
//   - slowloris: a connection held open through the stream layer: reliable.
//   - arp_spoof: keyed on the sender MAC, which is the identity: reliable.
//   - dns_tunnel and dns_nxdomain_burst are about the client's own
//     queries: reliable over TCP (the client completed a handshake),
//     spoofable over UDP.
//   - Every other detector counts packets whose source is not verified
//     (SYNs of incomplete handshakes, UDP, ICMP, fragments, TTLs, rates):
//     spoofable.
//   - Signature rules on TCP: reliable on a flow whose handshake the
//     tracker saw complete, for stream_anomaly rules (the stream layer)
//     and for application-layer rules (app_proto, app_field and the
//     other per-message options, which need a reassembled stream);
//     otherwise spoofable. Signature rules on UDP, ICMP, other IP and
//     ARP: spoofable.
func reliable(r *Rule, v *view) bool {
	switch r.Detect {
	case DetectBeacon, DetectSlowloris, DetectARPSpoof:
		return true
	case DetectDNSTunnel, DetectNXDomainBurst:
		return v.g == gTCP
	case "":
		return v.g == gTCP && (v.established || r.hasAnomaly || r.appProto != "" || r.perMessage())
	}
	return false
}

func attribution(r *Rule, v *view) string {
	if reliable(r, v) {
		return attrReliable
	}
	return attrSpoofable
}
