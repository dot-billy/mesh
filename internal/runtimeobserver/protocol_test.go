package runtimeobserver

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
)

const testNonce = "0123456789abcdef0123456789abcdef"

func TestNewRequestIsCanonicalAndFresh(t *testing.T) {
	t.Parallel()
	seen := make(map[string]struct{}, 128)
	for range 128 {
		request, err := NewRequest()
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		if !validNonce(request.Nonce) {
			t.Fatalf("nonce is not 32 lowercase hex: %q", request.Nonce)
		}
		if _, duplicate := seen[request.Nonce]; duplicate {
			t.Fatalf("duplicate CSPRNG nonce: %q", request.Nonce)
		}
		seen[request.Nonce] = struct{}{}
		line, err := EncodeRequestLine(request)
		if err != nil {
			t.Fatalf("EncodeRequestLine: %v", err)
		}
		expected := fmt.Sprintf("{\"schema\":%q,\"operation\":%q,\"nonce\":%q}\n", RequestSchema, SnapshotOp, request.Nonce)
		if string(line) != expected || len(line) > MaxRequestBytes {
			t.Fatalf("noncanonical request: %q", line)
		}
		decoded, err := DecodeRequestLine(line)
		if err != nil || decoded != request {
			t.Fatalf("DecodeRequestLine = %#v, %v", decoded, err)
		}
	}
}

func TestDecodeRequestLineRejectsNoncanonicalAndMalformedInput(t *testing.T) {
	t.Parallel()
	canonical := []byte(fmt.Sprintf("{\"schema\":%q,\"operation\":%q,\"nonce\":%q}\n", RequestSchema, SnapshotOp, testNonce))
	tests := map[string][]byte{
		"empty":           nil,
		"missing newline": canonical[:len(canonical)-1],
		"crlf":            append(append([]byte(nil), canonical[:len(canonical)-1]...), '\r', '\n'),
		"extra newline":   append(append([]byte(nil), canonical...), '\n'),
		"trailing object": []byte(strings.TrimSuffix(string(canonical), "\n") + "{}\n"),
		"leading space":   append([]byte(" "), canonical...),
		"reordered":       []byte(fmt.Sprintf("{\"operation\":%q,\"schema\":%q,\"nonce\":%q}\n", SnapshotOp, RequestSchema, testNonce)),
		"duplicate":       []byte(fmt.Sprintf("{\"schema\":%q,\"operation\":%q,\"nonce\":%q,\"nonce\":%q}\n", RequestSchema, SnapshotOp, testNonce, testNonce)),
		"unknown":         []byte(fmt.Sprintf("{\"schema\":%q,\"operation\":%q,\"nonce\":%q,\"peer\":\"10.42.0.1\"}\n", RequestSchema, SnapshotOp, testNonce)),
		"missing":         []byte(fmt.Sprintf("{\"schema\":%q,\"nonce\":%q}\n", RequestSchema, testNonce)),
		"wrong operation": []byte(fmt.Sprintf("{\"schema\":%q,\"operation\":\"reload\",\"nonce\":%q}\n", RequestSchema, testNonce)),
		"wrong schema":    []byte(fmt.Sprintf("{\"schema\":\"nebula.runtime-observer.request.v2\",\"operation\":%q,\"nonce\":%q}\n", SnapshotOp, testNonce)),
		"uppercase nonce": []byte(fmt.Sprintf("{\"schema\":%q,\"operation\":%q,\"nonce\":\"0123456789ABCDEF0123456789ABCDEF\"}\n", RequestSchema, SnapshotOp)),
		"short nonce":     []byte(fmt.Sprintf("{\"schema\":%q,\"operation\":%q,\"nonce\":\"00\"}\n", RequestSchema, SnapshotOp)),
		"escaped schema":  []byte(fmt.Sprintf("{\"schema\":\"\\u006eebula.runtime-observer.request.v1\",\"operation\":%q,\"nonce\":%q}\n", SnapshotOp, testNonce)),
		"oversized":       append(bytes.Repeat([]byte{' '}, MaxRequestBytes), '\n'),
	}
	for name, message := range tests {
		message := message
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := DecodeRequestLine(message); !errors.Is(err, ErrProtocol) {
				t.Fatalf("DecodeRequestLine error = %v, want ErrProtocol", err)
			}
		})
	}
}

func TestValidationContextRequiresVerifiedIPv4Topology(t *testing.T) {
	t.Parallel()
	network := netip.MustParsePrefix("10.42.0.0/24")
	lighthouses := []netip.Addr{netip.MustParseAddr("10.42.0.2"), netip.MustParseAddr("10.42.0.1")}
	validation, err := NewValidationContext(network, lighthouses)
	if err != nil {
		t.Fatalf("NewValidationContext: %v", err)
	}
	if got := validation.lighthouses; len(got) != 2 || got[0].String() != "10.42.0.1" || got[1].String() != "10.42.0.2" {
		t.Fatalf("sorted copied lighthouses = %v", got)
	}
	lighthouses[0] = netip.MustParseAddr("10.42.0.99")
	if validation.lighthouses[1].String() != "10.42.0.2" {
		t.Fatal("validation context retained the caller's mutable slice")
	}

	tooMany := make([]netip.Addr, MaxConfiguredLighthouses+1)
	for index := range tooMany {
		tooMany[index] = netip.AddrFrom4([4]byte{10, 0, byte(index >> 8), byte(index)})
	}
	tests := map[string]struct {
		network     netip.Prefix
		lighthouses []netip.Addr
	}{
		"zero context":       {},
		"unmasked prefix":    {network: netip.MustParsePrefix("10.42.0.7/24")},
		"IPv6 prefix":        {network: netip.MustParsePrefix("fd00::/64")},
		"IPv6 lighthouse":    {network: network, lighthouses: []netip.Addr{netip.MustParseAddr("fd00::1")}},
		"outside network":    {network: network, lighthouses: []netip.Addr{netip.MustParseAddr("10.43.0.1")}},
		"duplicate address":  {network: network, lighthouses: []netip.Addr{netip.MustParseAddr("10.42.0.1"), netip.MustParseAddr("10.42.0.1")}},
		"configured set cap": {network: netip.MustParsePrefix("10.0.0.0/8"), lighthouses: tooMany},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := NewValidationContext(test.network, test.lighthouses); !errors.Is(err, ErrProtocol) {
				t.Fatalf("NewValidationContext error = %v, want ErrProtocol", err)
			}
		})
	}
}

func TestSnapshotRoundTripAndNullableAges(t *testing.T) {
	t.Parallel()
	validation := testValidation(t, "10.42.0.1", "10.42.0.2")
	snapshot := validSnapshot()
	line, err := EncodeSnapshotLine(snapshot, testNonce, validation)
	if err != nil {
		t.Fatalf("EncodeSnapshotLine: %v", err)
	}
	if len(line) > MaxResponseBytes || line[len(line)-1] != '\n' {
		t.Fatalf("invalid response frame length=%d", len(line))
	}
	decoded, err := DecodeSnapshotLine(line, testNonce, validation)
	if err != nil {
		t.Fatalf("DecodeSnapshotLine: %v", err)
	}
	if !snapshotsEqual(snapshot, decoded) {
		t.Fatalf("round trip mismatch\nwant: %#v\n got: %#v", snapshot, decoded)
	}

	none := validSnapshot()
	none.Handshakes.CompletedTotal = 0
	none.Handshakes.MostRecentCompletionAgeMS = nil
	none.Peers = PeerSnapshot{}
	none.Lighthouses.Established = 0
	none.Lighthouses.AuthenticatedRXWithin2m = 0
	none.Lighthouses.AuthenticatedRXWithin5m = 0
	none.Lighthouses.Entries = []LighthouseEntry{}
	line, err = EncodeSnapshotLine(none, testNonce, validation)
	if err != nil {
		t.Fatalf("EncodeSnapshotLine with null ages: %v", err)
	}
	if !bytes.Contains(line, []byte(`"most_recent_completion_age_ms":null`)) || !bytes.Contains(line, []byte(`"entries":[]`)) {
		t.Fatalf("nullable/canonical representation missing: %s", line)
	}
	if _, err := DecodeSnapshotLine(line, testNonce, validation); err != nil {
		t.Fatalf("DecodeSnapshotLine with null ages: %v", err)
	}
}

func TestSnapshotRetainsConfiguredLighthouseRXAfterTunnelEviction(t *testing.T) {
	t.Parallel()
	validation := testValidation(t, "10.42.0.1")
	retainedAge := uint64(120_000)
	snapshot := validSnapshot()
	snapshot.Lighthouses = LighthouseSnapshot{
		Configured:                     1,
		MostRecentAuthenticatedRXAgeMS: &retainedAge,
		Entries:                        []LighthouseEntry{},
	}
	snapshot.Peers = PeerSnapshot{}

	line, err := EncodeSnapshotLine(snapshot, testNonce, validation)
	if err != nil {
		t.Fatalf("EncodeSnapshotLine retained lighthouse RX: %v", err)
	}
	decoded, err := DecodeSnapshotLine(line, testNonce, validation)
	if err != nil {
		t.Fatalf("DecodeSnapshotLine retained lighthouse RX: %v", err)
	}
	if decoded.Lighthouses.Established != 0 || decoded.Lighthouses.MostRecentAuthenticatedRXAgeMS == nil ||
		*decoded.Lighthouses.MostRecentAuthenticatedRXAgeMS != retainedAge {
		t.Fatalf("retained lighthouse RX changed: %#v", decoded.Lighthouses)
	}
}

func TestDecodeSnapshotLineAcceptsStrictV1WithoutRetainedHistory(t *testing.T) {
	t.Parallel()
	validation := testValidation(t)
	legacy := []byte(`{"schema":"nebula.runtime-observer.snapshot.v1","nonce":"` + testNonce + `","process_instance_id":"fedcba9876543210fedcba9876543210","sample_sequence":1,"process_uptime_ms":0,"handshakes":{"completed_total":0,"timed_out_total":0,"pending":0,"most_recent_completion_age_ms":null},"peers":{"established":0,"authenticated_rx_within_2m":0,"authenticated_rx_within_5m":0,"oldest_authenticated_rx_age_ms":null},"lighthouses":{"configured":0,"established":0,"authenticated_rx_within_2m":0,"authenticated_rx_within_5m":0,"overflow":false,"entries":[]}}` + "\n")

	decoded, err := DecodeSnapshotLine(legacy, testNonce, validation)
	if err != nil {
		t.Fatalf("DecodeSnapshotLine legacy v1: %v", err)
	}
	if decoded.Schema != SnapshotSchemaV1 || decoded.Lighthouses.MostRecentAuthenticatedRXAgeMS != nil {
		t.Fatalf("legacy v1 was not represented safely: %#v", decoded)
	}

	withV2Field := bytes.Replace(legacy, []byte(`"overflow":false`), []byte(`"most_recent_authenticated_rx_age_ms":null,"overflow":false`), 1)
	if _, err := DecodeSnapshotLine(withV2Field, testNonce, validation); !errors.Is(err, ErrProtocol) {
		t.Fatalf("v1 with a v2 field error = %v, want ErrProtocol", err)
	}
}

func TestDecodeSnapshotRejectsMalformedAllowlist(t *testing.T) {
	t.Parallel()
	validation := testValidation(t, "10.42.0.1", "10.42.0.2")
	valid := rawSnapshot(validSnapshot())
	replace := func(old, replacement string) []byte {
		t.Helper()
		if !strings.Contains(string(valid), old) {
			t.Fatalf("fixture does not contain %q", old)
		}
		return []byte(strings.Replace(string(valid), old, replacement, 1))
	}
	tests := map[string][]byte{
		"empty":                  nil,
		"missing newline":        valid[:len(valid)-1],
		"crlf":                   append(append([]byte(nil), valid[:len(valid)-1]...), '\r', '\n'),
		"extra newline":          append(append([]byte(nil), valid...), '\n'),
		"trailing object":        []byte(strings.TrimSuffix(string(valid), "\n") + "{}\n"),
		"unknown top field":      replace(`{"schema":`, `{"secret":"forbidden","schema":`),
		"duplicate top field":    replace(`"nonce":"`+testNonce+`"`, `"nonce":"`+testNonce+`","nonce":"`+testNonce+`"`),
		"missing top field":      replace(`"sample_sequence":42,`, ``),
		"unknown nested field":   replace(`"handshakes":{`, `"handshakes":{"debug":"forbidden",`),
		"duplicate nested field": replace(`"completed_total":8`, `"completed_total":8,"completed_total":8`),
		"unknown entry field":    replace(`"vpn_ip":"10.42.0.1"`, `"underlay":"192.0.2.1","vpn_ip":"10.42.0.1"`),
		"duplicate entry field":  replace(`"vpn_ip":"10.42.0.1"`, `"vpn_ip":"10.42.0.1","vpn_ip":"10.42.0.1"`),
		"string integer":         replace(`"sample_sequence":42`, `"sample_sequence":"42"`),
		"exponent integer":       replace(`"sample_sequence":42`, `"sample_sequence":4.2e1`),
		"negative integer":       replace(`"sample_sequence":42`, `"sample_sequence":-1`),
		"leading-zero integer":   replace(`"sample_sequence":42`, `"sample_sequence":042`),
		"null object":            replace(`"handshakes":{`, `"handshakes":null,"discarded":{`),
		"escaped schema":         replace(`"schema":"nebula.runtime-observer.snapshot.v2"`, `"schema":"\\u006eebula.runtime-observer.snapshot.v2"`),
		"oversized":              append(bytes.Repeat([]byte{' '}, MaxResponseBytes), '\n'),
	}
	for name, message := range tests {
		message := message
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := DecodeSnapshotLine(message, testNonce, validation); !errors.Is(err, ErrProtocol) {
				t.Fatalf("DecodeSnapshotLine error = %v, want ErrProtocol", err)
			}
		})
	}
}

func TestDecodeSnapshotRejectsImpossibleValues(t *testing.T) {
	t.Parallel()
	baseValidation := testValidation(t, "10.42.0.1", "10.42.0.2")
	tests := map[string]func(*Snapshot){
		"wrong schema":       func(snapshot *Snapshot) { snapshot.Schema += ".future" },
		"wrong nonce":        func(snapshot *Snapshot) { snapshot.Nonce = strings.Repeat("f", NonceHexLength) },
		"bad instance id":    func(snapshot *Snapshot) { snapshot.ProcessInstanceID = strings.Repeat("A", NonceHexLength) },
		"sequence overflow":  func(snapshot *Snapshot) { snapshot.SampleSequence = MaxExactJSONInteger + 1 },
		"uptime overflow":    func(snapshot *Snapshot) { snapshot.ProcessUptimeMS = MaxExactJSONInteger + 1 },
		"completed overflow": func(snapshot *Snapshot) { snapshot.Handshakes.CompletedTotal = MaxExactJSONInteger + 1 },
		"pending overflow":   func(snapshot *Snapshot) { snapshot.Handshakes.Pending = MaxAggregateCount + 1 },
		"age saturation overflow": func(snapshot *Snapshot) {
			snapshot.Handshakes.MostRecentCompletionAgeMS = uintPointer(MaxAgeMilliseconds + 1)
		},
		"handshake age exceeds uptime": func(snapshot *Snapshot) {
			snapshot.Handshakes.MostRecentCompletionAgeMS = uintPointer(snapshot.ProcessUptimeMS + 1)
		},
		"peer age exceeds uptime": func(snapshot *Snapshot) {
			snapshot.Peers.OldestAuthenticatedRXAgeMS = uintPointer(snapshot.ProcessUptimeMS + 1)
		},
		"lighthouse retained age exceeds uptime": func(snapshot *Snapshot) {
			snapshot.Lighthouses.MostRecentAuthenticatedRXAgeMS = uintPointer(snapshot.ProcessUptimeMS + 1)
		},
		"entry age exceeds uptime": func(snapshot *Snapshot) {
			snapshot.Lighthouses.Entries[0].LastHandshakeAgeMS = uintPointer(snapshot.ProcessUptimeMS + 1)
		},
		"zero completions with age":                  func(snapshot *Snapshot) { snapshot.Handshakes.CompletedTotal = 0 },
		"completions without age":                    func(snapshot *Snapshot) { snapshot.Handshakes.MostRecentCompletionAgeMS = nil },
		"fewer completions than peers":               func(snapshot *Snapshot) { snapshot.Handshakes.CompletedTotal = 2 },
		"peer two-minute count exceeds five":         func(snapshot *Snapshot) { snapshot.Peers.AuthenticatedRXWithin2m = 3 },
		"peer five-minute count exceeds established": func(snapshot *Snapshot) { snapshot.Peers.AuthenticatedRXWithin5m = 4 },
		"peer recent count without age":              func(snapshot *Snapshot) { snapshot.Peers.OldestAuthenticatedRXAgeMS = nil },
		"peer age without established": func(snapshot *Snapshot) {
			snapshot.Peers.Established = 0
			snapshot.Peers.AuthenticatedRXWithin2m = 0
			snapshot.Peers.AuthenticatedRXWithin5m = 0
		},
		"lighthouse established exceeds configured": func(snapshot *Snapshot) { snapshot.Lighthouses.Established = 3 },
		"lighthouse counts not derived":             func(snapshot *Snapshot) { snapshot.Lighthouses.AuthenticatedRXWithin2m = 1 },
		"lighthouse current receive without retained aggregate": func(snapshot *Snapshot) {
			snapshot.Lighthouses.MostRecentAuthenticatedRXAgeMS = nil
		},
		"lighthouse retained aggregate older than current entry": func(snapshot *Snapshot) {
			snapshot.Lighthouses.MostRecentAuthenticatedRXAgeMS = uintPointer(1_000)
		},
		"overflow false for large set": func(snapshot *Snapshot) { snapshot.Lighthouses.Overflow = true },
		"entry outside topology":       func(snapshot *Snapshot) { snapshot.Lighthouses.Entries[0].VPNIP = "10.42.0.3" },
		"entry outside network":        func(snapshot *Snapshot) { snapshot.Lighthouses.Entries[0].VPNIP = "10.43.0.1" },
		"noncanonical IPv4":            func(snapshot *Snapshot) { snapshot.Lighthouses.Entries[0].VPNIP = "10.42.0.01" },
		"IPv6 entry":                   func(snapshot *Snapshot) { snapshot.Lighthouses.Entries[0].VPNIP = "fd00::1" },
		"unsorted entries": func(snapshot *Snapshot) {
			snapshot.Lighthouses.Entries[0], snapshot.Lighthouses.Entries[1] = snapshot.Lighthouses.Entries[1], snapshot.Lighthouses.Entries[0]
		},
		"duplicate entries": func(snapshot *Snapshot) {
			snapshot.Lighthouses.Entries[1].VPNIP = snapshot.Lighthouses.Entries[0].VPNIP
		},
		"established without handshake": func(snapshot *Snapshot) { snapshot.Lighthouses.Entries[0].LastHandshakeAgeMS = nil },
		"authenticated without handshake": func(snapshot *Snapshot) {
			snapshot.Lighthouses.Entries[0].Established = false
			snapshot.Lighthouses.Entries[0].LastHandshakeAgeMS = nil
		},
		"lighthouse exceeds peer aggregate": func(snapshot *Snapshot) {
			snapshot.Peers.Established = 1
			snapshot.Peers.AuthenticatedRXWithin2m = 1
			snapshot.Peers.AuthenticatedRXWithin5m = 1
		},
	}
	for name, mutate := range tests {
		mutate := mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			snapshot := validSnapshot()
			mutate(&snapshot)
			if _, err := DecodeSnapshotLine(rawSnapshot(snapshot), testNonce, baseValidation); !errors.Is(err, ErrProtocol) {
				t.Fatalf("DecodeSnapshotLine error = %v, want ErrProtocol", err)
			}
		})
	}

	t.Run("configured topology count mismatch", func(t *testing.T) {
		snapshot := validSnapshot()
		validation := testValidation(t, "10.42.0.1", "10.42.0.2", "10.42.0.3")
		if _, err := DecodeSnapshotLine(rawSnapshot(snapshot), testNonce, validation); !errors.Is(err, ErrProtocol) {
			t.Fatalf("DecodeSnapshotLine error = %v, want ErrProtocol", err)
		}
	})
}

func TestLighthouseOverflowIsBoundedAndCoherent(t *testing.T) {
	t.Parallel()
	addresses := make([]string, 9)
	entries := make([]LighthouseEntry, MaxLighthouseEntries)
	for index := range addresses {
		addresses[index] = fmt.Sprintf("10.42.0.%d", index+1)
		if index < len(entries) {
			entries[index] = LighthouseEntry{
				VPNIP:                    addresses[index],
				Established:              true,
				LastHandshakeAgeMS:       uintPointer(500),
				LastAuthenticatedRXAgeMS: uintPointer(500),
			}
		}
	}
	validation := testValidation(t, addresses...)
	snapshot := validSnapshot()
	snapshot.Handshakes.CompletedTotal = 9
	snapshot.Peers = PeerSnapshot{Established: 9, AuthenticatedRXWithin2m: 9, AuthenticatedRXWithin5m: 9, OldestAuthenticatedRXAgeMS: uintPointer(500)}
	snapshot.Lighthouses = LighthouseSnapshot{
		Configured: 9, Established: 9, AuthenticatedRXWithin2m: 9, AuthenticatedRXWithin5m: 9,
		MostRecentAuthenticatedRXAgeMS: uintPointer(500), Overflow: true, Entries: entries,
	}
	if _, err := DecodeSnapshotLine(rawSnapshot(snapshot), testNonce, validation); err != nil {
		t.Fatalf("valid overflow snapshot rejected: %v", err)
	}

	tooManyEntries := snapshot
	tooManyEntries.Lighthouses.Entries = append(append([]LighthouseEntry(nil), entries...), LighthouseEntry{
		VPNIP: "10.42.0.9", Established: true, LastHandshakeAgeMS: uintPointer(500), LastAuthenticatedRXAgeMS: uintPointer(500),
	})
	if _, err := DecodeSnapshotLine(rawSnapshot(tooManyEntries), testNonce, validation); !errors.Is(err, ErrProtocol) {
		t.Fatalf("nine entries error = %v, want ErrProtocol", err)
	}

	impossibleAggregate := snapshot
	impossibleAggregate.Lighthouses.Established = 7
	impossibleAggregate.Lighthouses.AuthenticatedRXWithin2m = 7
	impossibleAggregate.Lighthouses.AuthenticatedRXWithin5m = 7
	if _, err := DecodeSnapshotLine(rawSnapshot(impossibleAggregate), testNonce, validation); !errors.Is(err, ErrProtocol) {
		t.Fatalf("truncated aggregate error = %v, want ErrProtocol", err)
	}
}

func TestNumericCeilingsAreAcceptedWithoutWrapping(t *testing.T) {
	t.Parallel()
	validation := testValidation(t)
	snapshot := Snapshot{
		Schema:            SnapshotSchema,
		Nonce:             testNonce,
		ProcessInstanceID: "fedcba9876543210fedcba9876543210",
		SampleSequence:    MaxExactJSONInteger,
		ProcessUptimeMS:   MaxExactJSONInteger,
		Handshakes: HandshakeSnapshot{
			CompletedTotal:            MaxExactJSONInteger,
			TimedOutTotal:             MaxExactJSONInteger,
			Pending:                   MaxAggregateCount,
			MostRecentCompletionAgeMS: uintPointer(MaxAgeMilliseconds),
		},
		Peers:       PeerSnapshot{},
		Lighthouses: LighthouseSnapshot{Entries: []LighthouseEntry{}},
	}
	line := rawSnapshot(snapshot)
	decoded, err := DecodeSnapshotLine(line, testNonce, validation)
	if err != nil {
		t.Fatalf("ceiling snapshot rejected: %v", err)
	}
	if decoded.SampleSequence != MaxExactJSONInteger || decoded.Handshakes.Pending != MaxAggregateCount ||
		decoded.Handshakes.MostRecentCompletionAgeMS == nil || *decoded.Handshakes.MostRecentCompletionAgeMS != MaxAgeMilliseconds {
		t.Fatalf("ceiling values changed: %#v", decoded)
	}
}

func TestLighthouseRetainedRXRequiresConfiguredAddress(t *testing.T) {
	t.Parallel()
	validation := testValidation(t)
	snapshot := validSnapshot()
	snapshot.Peers = PeerSnapshot{}
	snapshot.Lighthouses = LighthouseSnapshot{
		MostRecentAuthenticatedRXAgeMS: uintPointer(1),
		Entries:                        []LighthouseEntry{},
	}
	if _, err := DecodeSnapshotLine(rawSnapshot(snapshot), testNonce, validation); !errors.Is(err, ErrProtocol) {
		t.Fatalf("DecodeSnapshotLine error = %v, want ErrProtocol", err)
	}
}

func validSnapshot() Snapshot {
	return Snapshot{
		Schema:            SnapshotSchema,
		Nonce:             testNonce,
		ProcessInstanceID: "fedcba9876543210fedcba9876543210",
		SampleSequence:    42,
		ProcessUptimeMS:   123456,
		Handshakes: HandshakeSnapshot{
			CompletedTotal:            8,
			TimedOutTotal:             1,
			Pending:                   0,
			MostRecentCompletionAgeMS: uintPointer(2200),
		},
		Peers: PeerSnapshot{
			Established:                3,
			AuthenticatedRXWithin2m:    2,
			AuthenticatedRXWithin5m:    2,
			OldestAuthenticatedRXAgeMS: uintPointer(17000),
		},
		Lighthouses: LighthouseSnapshot{
			Configured:                     2,
			Established:                    2,
			AuthenticatedRXWithin2m:        2,
			AuthenticatedRXWithin5m:        2,
			MostRecentAuthenticatedRXAgeMS: uintPointer(900),
			Entries: []LighthouseEntry{
				{VPNIP: "10.42.0.1", Established: true, LastHandshakeAgeMS: uintPointer(2200), LastAuthenticatedRXAgeMS: uintPointer(900)},
				{VPNIP: "10.42.0.2", Established: true, LastHandshakeAgeMS: uintPointer(4000), LastAuthenticatedRXAgeMS: uintPointer(17000)},
			},
		},
	}
}

func testValidation(t *testing.T, addresses ...string) ValidationContext {
	t.Helper()
	lighthouses := make([]netip.Addr, len(addresses))
	for index, address := range addresses {
		lighthouses[index] = netip.MustParseAddr(address)
	}
	validation, err := NewValidationContext(netip.MustParsePrefix("10.42.0.0/24"), lighthouses)
	if err != nil {
		t.Fatalf("NewValidationContext: %v", err)
	}
	return validation
}

func rawSnapshot(snapshot Snapshot) []byte {
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		panic(err)
	}
	return append(encoded, '\n')
}

func uintPointer(value uint64) *uint64 {
	return &value
}

func snapshotsEqual(left, right Snapshot) bool {
	leftJSON, _ := json.Marshal(left)
	rightJSON, _ := json.Marshal(right)
	return bytes.Equal(leftJSON, rightJSON)
}
