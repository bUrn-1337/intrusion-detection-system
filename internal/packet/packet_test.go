package packet

import (
	"slices"
	"testing"
	"time"
)

var testTS = time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)

func TestNewParsedPacket(t *testing.T) {
	p := NewParsedPacket(testTS, 60, 1514)

	if !p.Timestamp.Equal(testTS) || p.CaptureLen != 60 || p.WireLen != 1514 {
		t.Errorf("capture fields = (%v, %d, %d), want (%v, 60, 1514)",
			p.Timestamp, p.CaptureLen, p.WireLen, testTS)
	}

	offsets := []struct {
		name string
		got  int
	}{
		{"L3Offset", p.L3Offset},
		{"L4Offset", p.L4Offset},
		{"PayloadOffset", p.PayloadOffset},
	}
	for _, o := range offsets {
		if o.got != -1 {
			t.Errorf("%s = %d, want -1", o.name, o.got)
		}
	}
}

func TestParsedPacketErrors(t *testing.T) {
	tests := []struct {
		name       string
		errs       []string
		wantHas    bool
		wantErrors []string
	}{
		{
			name:       "no errors",
			errs:       nil,
			wantHas:    false,
			wantErrors: nil,
		},
		{
			name:       "two errors kept in order",
			errs:       []string{"lower: truncated IPv4 header", "upper: bad TCP data offset"},
			wantHas:    true,
			wantErrors: []string{"lower: truncated IPv4 header", "upper: bad TCP data offset"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewParsedPacket(testTS, 60, 1514)
			if p.HasErrors() {
				t.Fatal("new packet HasErrors() = true, want false")
			}

			for _, e := range tt.errs {
				p.AddError(e)
			}

			if got := p.HasErrors(); got != tt.wantHas {
				t.Errorf("HasErrors() = %v, want %v", got, tt.wantHas)
			}
			if !slices.Equal(p.ParseErrors, tt.wantErrors) {
				t.Errorf("ParseErrors = %q, want %q", p.ParseErrors, tt.wantErrors)
			}
		})
	}
}

func TestPayload(t *testing.T) {
	raw := []byte{0, 1, 2, 3, 4, 5, 6, 7}

	tests := []struct {
		name   string
		raw    []byte
		offset int
		want   []byte
	}{
		{"valid offset", raw, 5, []byte{5, 6, 7}},
		{"offset zero", raw, 0, raw},
		{"offset at end is empty", raw, len(raw), []byte{}},
		{"not determined", raw, -1, nil},
		{"negative", raw, -42, nil},
		{"past end", raw, len(raw) + 1, nil},
		{"nil RawData", nil, 0, nil},
		{"nil RawData past end", nil, 3, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewParsedPacket(testTS, uint32(len(tt.raw)), uint32(len(tt.raw)))
			p.RawData = tt.raw
			p.PayloadOffset = tt.offset

			got := p.Payload()
			if !slices.Equal(got, tt.want) {
				t.Errorf("Payload() = %v, want %v", got, tt.want)
			}
			if (tt.want == nil) != (got == nil) {
				t.Errorf("Payload() nil = %v, want nil = %v", got == nil, tt.want == nil)
			}
		})
	}
}

func TestPayloadExcludesPadding(t *testing.T) {
	// 14 Ethernet + 20 IPv4 + 8 UDP + 2 payload = 44 bytes, padded to 60.
	raw := make([]byte, 60)
	raw[42], raw[43] = 'h', 'i'
	p := NewParsedPacket(testTS, 60, 60)
	p.RawData = raw
	p.IPVersion = 4
	p.L3Offset = 14
	p.IPTotalLen = 30
	p.PayloadOffset = 42

	if got := p.Payload(); string(got) != "hi" {
		t.Errorf("Payload() = %q, want %q", got, "hi")
	}
	p.PayloadOffset = 50 // inside the padding
	if got := p.Payload(); got != nil {
		t.Errorf("Payload() with offset in padding = %v, want nil", got)
	}
}

func TestIPEnd(t *testing.T) {
	raw := make([]byte, 60)

	tests := []struct {
		name     string
		raw      []byte
		version  uint8
		l3       int
		totalLen uint32
		want     int
	}{
		{"padded frame", raw, 4, 14, 30, 44},
		{"exact fit", raw, 6, 14, 46, 60},
		{"snaplen truncated", raw, 4, 14, 1500, 60},
		{"huge length", raw, 4, 14, 0xFFFFFFFF, 60},
		{"zero length", raw, 4, 14, 0, 14},
		{"no IP header", raw, 0, 14, 30, -1},
		{"L3 not determined", raw, 4, -1, 30, -1},
		{"L3 past end", raw, 4, 61, 30, -1},
		{"L3 at end", raw, 4, 60, 30, 60},
		{"nil RawData", nil, 4, 0, 30, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewParsedPacket(testTS, uint32(len(tt.raw)), uint32(len(tt.raw)))
			p.RawData = tt.raw
			p.IPVersion = tt.version
			p.L3Offset = tt.l3
			p.IPTotalLen = tt.totalLen
			if got := p.IPEnd(); got != tt.want {
				t.Errorf("IPEnd() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestSetAppField(t *testing.T) {
	tests := []struct {
		name   string
		fields map[string]string
	}{
		{"nil map", nil},
		{"existing map", map[string]string{"host": "example.com"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewParsedPacket(testTS, 60, 60)
			p.AppFields = tt.fields

			p.SetAppField("method", "GET")

			if got := p.AppFields["method"]; got != "GET" {
				t.Errorf(`AppFields["method"] = %q, want "GET"`, got)
			}
			for k, v := range tt.fields {
				if p.AppFields[k] != v {
					t.Errorf("AppFields[%q] = %q, want %q", k, p.AppFields[k], v)
				}
			}
		})
	}
}

func TestAddAppReason(t *testing.T) {
	type call struct{ kind, reason string }

	tests := []struct {
		name       string
		calls      []call
		wantFields map[string]string
		wantErrors int
	}{
		{
			name:       "single malformed",
			calls:      []call{{ReasonMalformed, "bad header"}},
			wantFields: map[string]string{"malformed_reason": "bad header"},
		},
		{
			name: "same kind twice keeps both in order",
			calls: []call{
				{ReasonSuspicious, "long uri"},
				{ReasonSuspicious, "basic auth over cleartext"},
			},
			wantFields: map[string]string{"suspicious_reason": "long uri;basic auth over cleartext"},
		},
		{
			name: "kinds stored separately",
			calls: []call{
				{ReasonMalformed, "bad qdcount"},
				{ReasonSuspicious, "long qname"},
			},
			wantFields: map[string]string{
				"malformed_reason":  "bad qdcount",
				"suspicious_reason": "long qname",
			},
		},
		{
			name:       "unknown kind recorded as parse error",
			calls:      []call{{"weird", "x"}},
			wantFields: nil,
			wantErrors: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewParsedPacket(testTS, 60, 60)

			for _, c := range tt.calls {
				p.AddAppReason(c.kind, c.reason)
			}

			if len(p.AppFields) != len(tt.wantFields) {
				t.Errorf("AppFields = %q, want %q", p.AppFields, tt.wantFields)
			}
			for k, v := range tt.wantFields {
				if p.AppFields[k] != v {
					t.Errorf("AppFields[%q] = %q, want %q", k, p.AppFields[k], v)
				}
			}
			if len(p.ParseErrors) != tt.wantErrors {
				t.Errorf("len(ParseErrors) = %d, want %d (%q)", len(p.ParseErrors), tt.wantErrors, p.ParseErrors)
			}
		})
	}
}
