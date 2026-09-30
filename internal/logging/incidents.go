package logging

import (
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/bUrn-1337/intrusion-detection-system/internal/rules"
)

// Incident tracking for the dashboard.
const (
	// MaxIncidents bounds the incidents the aggregator keeps; the least
	// recently updated goes first.
	MaxIncidents = 500
	// IncidentIdle is how long an incident stays active without an
	// update, in alert (engine) time: the correlator's history length.
	IncidentIdle = 24 * time.Hour
)

// Incident is the latest state of one incident, from its incident and
// incident_update alerts.
type Incident struct {
	ID           string
	Kind         string // multi_stage, compromised_host, callback
	SID          int
	Msg          string
	Severity     string
	Score        int
	Entity       string // who, e.g. "192.0.2.1 -> 198.51.100.10"
	Chain        string // e.g. "recon -> exploit -> c2"
	Contributing int
	Updates      int // incident_update alerts since the incident alert
	FirstSeen    time.Time
	LastSeen     time.Time
}

// IsIncident reports whether a is an incident or incident update.
func IsIncident(a *rules.Alert) bool {
	return a.Kind == rules.KindIncident || a.Kind == rules.KindIncidentUpdate
}

// incident records an incident or incident_update alert.
func (a *Aggregator) incident(al *rules.Alert) {
	if al.Time.After(a.alertClock) {
		a.alertClock = al.Time
	}
	id := al.Details["incident_id"]
	in, ok := a.incidents[id]
	if !ok {
		if len(a.incidents) >= MaxIncidents {
			var oldest *Incident
			for _, x := range a.incidents {
				if oldest == nil || x.LastSeen.Before(oldest.LastSeen) {
					oldest = x
				}
			}
			delete(a.incidents, oldest.ID)
		}
		in = &Incident{ID: id}
		a.incidents[id] = in
	} else if al.Kind == rules.KindIncidentUpdate {
		in.Updates++
	}
	if al.Kind == rules.KindIncident {
		in.Updates = 0
	}
	score, _ := strconv.Atoi(al.Details["score"])
	n, _ := strconv.Atoi(al.Details["contributing_total"])
	in.Kind, in.SID, in.Msg, in.Severity, in.Score = al.Details["kind"], al.SID, al.Msg, al.Severity, score
	in.Entity, in.Chain, in.Contributing = al.Details["entity"], al.Details["chain"], n
	in.FirstSeen, in.LastSeen = al.FirstSeen, al.Time
}

// activeIncidents drops idle incidents and returns the rest, most severe
// first, then by score, then newest.
func (a *Aggregator) activeIncidents() []Incident {
	out := make([]Incident, 0, len(a.incidents))
	for id, in := range a.incidents {
		if a.alertClock.Sub(in.LastSeen) > IncidentIdle {
			delete(a.incidents, id)
			continue
		}
		out = append(out, *in)
	}
	SortIncidents(out)
	return out
}

// SortIncidents orders incidents most severe first, then by score, then
// most recently updated.
func SortIncidents(in []Incident) {
	sort.Slice(in, func(i, j int) bool {
		x, y := &in[i], &in[j]
		if r1, r2 := severityRank(x.Severity), severityRank(y.Severity); r1 != r2 {
			return r1 > r2
		}
		if x.Score != y.Score {
			return x.Score > y.Score
		}
		if !x.LastSeen.Equal(y.LastSeen) {
			return x.LastSeen.After(y.LastSeen)
		}
		return strings.Compare(x.ID, y.ID) < 0
	})
}
