// Package runtimeobserver implements the strictly bounded, read-only client
// side of the Nebula runtime-observer protocol. It does not persist telemetry
// or expose a listener.
package runtimeobserver

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"sort"
	"strconv"
)

const (
	RequestSchema    = "nebula.runtime-observer.request.v1"
	SnapshotSchemaV1 = "nebula.runtime-observer.snapshot.v1"
	SnapshotSchemaV2 = "nebula.runtime-observer.snapshot.v2"
	SnapshotSchema   = SnapshotSchemaV2
	SnapshotOp       = "snapshot"

	NonceBytes               = 16
	NonceHexLength           = NonceBytes * 2
	MaxRequestBytes          = 256
	MaxResponseBytes         = 16 << 10
	MaxLighthouseEntries     = 8
	MaxConfiguredLighthouses = 64
	MaxExactJSONInteger      = uint64(1<<53 - 1)
	MaxAggregateCount        = uint64(1<<32 - 1)
	MaxAgeMilliseconds       = MaxExactJSONInteger
	AuthenticatedRX2mLimit   = uint64(2 * 60 * 1000)
	AuthenticatedRX5mLimit   = uint64(5 * 60 * 1000)
)

var ErrProtocol = errors.New("runtime observer protocol violation")

// Request is the only request accepted by the v1 observer. Callers should use
// NewRequest rather than constructing one directly.
type Request struct {
	Schema    string `json:"schema"`
	Operation string `json:"operation"`
	Nonce     string `json:"nonce"`
}

// Snapshot is the complete current response allowlist. Pointer ages encode the
// protocol's distinction between a nonnegative age and an event that has not
// occurred in this process instance.
type Snapshot struct {
	Schema            string             `json:"schema"`
	Nonce             string             `json:"nonce"`
	ProcessInstanceID string             `json:"process_instance_id"`
	SampleSequence    uint64             `json:"sample_sequence"`
	ProcessUptimeMS   uint64             `json:"process_uptime_ms"`
	Handshakes        HandshakeSnapshot  `json:"handshakes"`
	Peers             PeerSnapshot       `json:"peers"`
	Lighthouses       LighthouseSnapshot `json:"lighthouses"`
}

type HandshakeSnapshot struct {
	CompletedTotal            uint64  `json:"completed_total"`
	TimedOutTotal             uint64  `json:"timed_out_total"`
	Pending                   uint64  `json:"pending"`
	MostRecentCompletionAgeMS *uint64 `json:"most_recent_completion_age_ms"`
}

type PeerSnapshot struct {
	Established                uint64  `json:"established"`
	AuthenticatedRXWithin2m    uint64  `json:"authenticated_rx_within_2m"`
	AuthenticatedRXWithin5m    uint64  `json:"authenticated_rx_within_5m"`
	OldestAuthenticatedRXAgeMS *uint64 `json:"oldest_authenticated_rx_age_ms"`
}

type LighthouseSnapshot struct {
	Configured                     uint64            `json:"configured"`
	Established                    uint64            `json:"established"`
	AuthenticatedRXWithin2m        uint64            `json:"authenticated_rx_within_2m"`
	AuthenticatedRXWithin5m        uint64            `json:"authenticated_rx_within_5m"`
	MostRecentAuthenticatedRXAgeMS *uint64           `json:"most_recent_authenticated_rx_age_ms"`
	Overflow                       bool              `json:"overflow"`
	Entries                        []LighthouseEntry `json:"entries"`
}

type LighthouseEntry struct {
	VPNIP                    string  `json:"vpn_ip"`
	Established              bool    `json:"established"`
	LastHandshakeAgeMS       *uint64 `json:"last_handshake_age_ms"`
	LastAuthenticatedRXAgeMS *uint64 `json:"last_authenticated_rx_age_ms"`
}

// snapshotV1 is retained only for strict, canonical decoding of an older
// observer. V1 had no process-retained lighthouse receive aggregate.
type snapshotV1 struct {
	Schema            string               `json:"schema"`
	Nonce             string               `json:"nonce"`
	ProcessInstanceID string               `json:"process_instance_id"`
	SampleSequence    uint64               `json:"sample_sequence"`
	ProcessUptimeMS   uint64               `json:"process_uptime_ms"`
	Handshakes        HandshakeSnapshot    `json:"handshakes"`
	Peers             PeerSnapshot         `json:"peers"`
	Lighthouses       lighthouseSnapshotV1 `json:"lighthouses"`
}

type lighthouseSnapshotV1 struct {
	Configured              uint64            `json:"configured"`
	Established             uint64            `json:"established"`
	AuthenticatedRXWithin2m uint64            `json:"authenticated_rx_within_2m"`
	AuthenticatedRXWithin5m uint64            `json:"authenticated_rx_within_5m"`
	Overflow                bool              `json:"overflow"`
	Entries                 []LighthouseEntry `json:"entries"`
}

// ValidationContext binds a snapshot to the already signature-verified local
// overlay and exact configured lighthouse set. Its fields are intentionally
// private so callers cannot bypass constructor validation after the fact.
// Construct it only from an active, verified Nebula configuration.
type ValidationContext struct {
	network     netip.Prefix
	lighthouses []netip.Addr
	valid       bool
}

// NewValidationContext validates and copies the expected topology. The
// lighthouse list is capped to keep validation work bounded independently of
// untrusted observer input.
func NewValidationContext(network netip.Prefix, lighthouses []netip.Addr) (ValidationContext, error) {
	if !network.IsValid() || !network.Addr().Is4() || network != network.Masked() || len(lighthouses) > MaxConfiguredLighthouses {
		return ValidationContext{}, ErrProtocol
	}
	copyOfLighthouses := append([]netip.Addr(nil), lighthouses...)
	for _, address := range copyOfLighthouses {
		if !address.IsValid() || !address.Is4() || !network.Contains(address) {
			return ValidationContext{}, ErrProtocol
		}
	}
	sort.Slice(copyOfLighthouses, func(left, right int) bool {
		leftBytes := copyOfLighthouses[left].As4()
		rightBytes := copyOfLighthouses[right].As4()
		return bytes.Compare(leftBytes[:], rightBytes[:]) < 0
	})
	for index := 1; index < len(copyOfLighthouses); index++ {
		if copyOfLighthouses[index] == copyOfLighthouses[index-1] {
			return ValidationContext{}, ErrProtocol
		}
	}
	return ValidationContext{network: network, lighthouses: copyOfLighthouses, valid: true}, nil
}

// NewRequest creates a request with a fresh, nonsecret 128-bit nonce.
func NewRequest() (Request, error) {
	var raw [NonceBytes]byte
	if _, err := io.ReadFull(rand.Reader, raw[:]); err != nil {
		return Request{}, ErrProtocol
	}
	return Request{
		Schema:    RequestSchema,
		Operation: SnapshotOp,
		Nonce:     hex.EncodeToString(raw[:]),
	}, nil
}

// EncodeRequestLine returns the one canonical v1 request representation.
func EncodeRequestLine(request Request) ([]byte, error) {
	if validateRequest(request) != nil {
		return nil, ErrProtocol
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		return nil, ErrProtocol
	}
	encoded = append(encoded, '\n')
	if len(encoded) > MaxRequestBytes {
		return nil, ErrProtocol
	}
	return encoded, nil
}

// DecodeRequestLine strictly accepts only the canonical, newline-terminated
// representation generated by EncodeRequestLine. It is provided so the
// upstream observer can share adversarial contract fixtures without growing a
// general RPC parser in Mesh.
func DecodeRequestLine(message []byte) (Request, error) {
	if !validLineFrame(message, MaxRequestBytes) {
		return Request{}, ErrProtocol
	}
	var request Request
	if decodeObject(message[:len(message)-1], []fieldDecoder{
		{name: "schema", decode: stringField(&request.Schema)},
		{name: "operation", decode: stringField(&request.Operation)},
		{name: "nonce", decode: stringField(&request.Nonce)},
	}) != nil || validateRequest(request) != nil {
		return Request{}, ErrProtocol
	}
	canonical, err := EncodeRequestLine(request)
	if err != nil || !bytes.Equal(message, canonical) {
		return Request{}, ErrProtocol
	}
	return request, nil
}

// EncodeSnapshotLine produces a bounded canonical fixture representation. The
// observer client does not use it to write to the socket.
func EncodeSnapshotLine(snapshot Snapshot, expectedNonce string, validation ValidationContext) ([]byte, error) {
	if validateSnapshot(snapshot, expectedNonce, validation) != nil {
		return nil, ErrProtocol
	}
	encoded, err := marshalSnapshot(snapshot)
	if err != nil {
		return nil, ErrProtocol
	}
	encoded = append(encoded, '\n')
	if len(encoded) > MaxResponseBytes {
		return nil, ErrProtocol
	}
	return encoded, nil
}

// DecodeSnapshotLine parses one bounded response with exact object schemas,
// rejects duplicate/unknown/missing fields at every level, and validates all
// cross-field invariants for current v2 and the exact legacy v1 fallback.
func DecodeSnapshotLine(message []byte, expectedNonce string, validation ValidationContext) (Snapshot, error) {
	if !validNonce(expectedNonce) || !validLineFrame(message, MaxResponseBytes) {
		return Snapshot{}, ErrProtocol
	}
	if snapshot, err := decodeSnapshotLineV2(message, expectedNonce, validation); err == nil {
		return snapshot, nil
	}
	if snapshot, err := decodeSnapshotLineV1(message, expectedNonce, validation); err == nil {
		return snapshot, nil
	}
	return Snapshot{}, ErrProtocol
}

func decodeSnapshotLineV2(message []byte, expectedNonce string, validation ValidationContext) (Snapshot, error) {
	var snapshot Snapshot
	if decodeObject(message[:len(message)-1], []fieldDecoder{
		{name: "schema", decode: stringField(&snapshot.Schema)},
		{name: "nonce", decode: stringField(&snapshot.Nonce)},
		{name: "process_instance_id", decode: stringField(&snapshot.ProcessInstanceID)},
		{name: "sample_sequence", decode: boundedUintField(&snapshot.SampleSequence, MaxExactJSONInteger)},
		{name: "process_uptime_ms", decode: boundedUintField(&snapshot.ProcessUptimeMS, MaxExactJSONInteger)},
		{name: "handshakes", decode: func(raw json.RawMessage) error { return decodeHandshakes(raw, &snapshot.Handshakes) }},
		{name: "peers", decode: func(raw json.RawMessage) error { return decodePeers(raw, &snapshot.Peers) }},
		{name: "lighthouses", decode: func(raw json.RawMessage) error { return decodeLighthouses(raw, &snapshot.Lighthouses) }},
	}) != nil || validateSnapshot(snapshot, expectedNonce, validation) != nil {
		return Snapshot{}, ErrProtocol
	}
	canonical, err := EncodeSnapshotLine(snapshot, expectedNonce, validation)
	if err != nil || !bytes.Equal(message, canonical) {
		return Snapshot{}, ErrProtocol
	}
	return snapshot, nil
}

func decodeSnapshotLineV1(message []byte, expectedNonce string, validation ValidationContext) (Snapshot, error) {
	var legacy snapshotV1
	if decodeObject(message[:len(message)-1], []fieldDecoder{
		{name: "schema", decode: stringField(&legacy.Schema)},
		{name: "nonce", decode: stringField(&legacy.Nonce)},
		{name: "process_instance_id", decode: stringField(&legacy.ProcessInstanceID)},
		{name: "sample_sequence", decode: boundedUintField(&legacy.SampleSequence, MaxExactJSONInteger)},
		{name: "process_uptime_ms", decode: boundedUintField(&legacy.ProcessUptimeMS, MaxExactJSONInteger)},
		{name: "handshakes", decode: func(raw json.RawMessage) error { return decodeHandshakes(raw, &legacy.Handshakes) }},
		{name: "peers", decode: func(raw json.RawMessage) error { return decodePeers(raw, &legacy.Peers) }},
		{name: "lighthouses", decode: func(raw json.RawMessage) error { return decodeLighthousesV1(raw, &legacy.Lighthouses) }},
	}) != nil {
		return Snapshot{}, ErrProtocol
	}
	snapshot := Snapshot{
		Schema: legacy.Schema, Nonce: legacy.Nonce, ProcessInstanceID: legacy.ProcessInstanceID,
		SampleSequence: legacy.SampleSequence, ProcessUptimeMS: legacy.ProcessUptimeMS,
		Handshakes: legacy.Handshakes, Peers: legacy.Peers,
		Lighthouses: LighthouseSnapshot{
			Configured: legacy.Lighthouses.Configured, Established: legacy.Lighthouses.Established,
			AuthenticatedRXWithin2m: legacy.Lighthouses.AuthenticatedRXWithin2m,
			AuthenticatedRXWithin5m: legacy.Lighthouses.AuthenticatedRXWithin5m,
			Overflow:                legacy.Lighthouses.Overflow, Entries: legacy.Lighthouses.Entries,
		},
	}
	if validateSnapshot(snapshot, expectedNonce, validation) != nil {
		return Snapshot{}, ErrProtocol
	}
	canonical, err := EncodeSnapshotLine(snapshot, expectedNonce, validation)
	if err != nil || !bytes.Equal(message, canonical) {
		return Snapshot{}, ErrProtocol
	}
	return snapshot, nil
}

func marshalSnapshot(snapshot Snapshot) ([]byte, error) {
	if snapshot.Schema != SnapshotSchemaV1 {
		return json.Marshal(snapshot)
	}
	return json.Marshal(snapshotV1{
		Schema: snapshot.Schema, Nonce: snapshot.Nonce, ProcessInstanceID: snapshot.ProcessInstanceID,
		SampleSequence: snapshot.SampleSequence, ProcessUptimeMS: snapshot.ProcessUptimeMS,
		Handshakes: snapshot.Handshakes, Peers: snapshot.Peers,
		Lighthouses: lighthouseSnapshotV1{
			Configured: snapshot.Lighthouses.Configured, Established: snapshot.Lighthouses.Established,
			AuthenticatedRXWithin2m: snapshot.Lighthouses.AuthenticatedRXWithin2m,
			AuthenticatedRXWithin5m: snapshot.Lighthouses.AuthenticatedRXWithin5m,
			Overflow:                snapshot.Lighthouses.Overflow, Entries: snapshot.Lighthouses.Entries,
		},
	})
}

func validateRequest(request Request) error {
	if request.Schema != RequestSchema || request.Operation != SnapshotOp || !validNonce(request.Nonce) {
		return ErrProtocol
	}
	return nil
}

func validateSnapshot(snapshot Snapshot, expectedNonce string, validation ValidationContext) error {
	if (snapshot.Schema != SnapshotSchemaV1 && snapshot.Schema != SnapshotSchemaV2) || !validNonce(expectedNonce) || snapshot.Nonce != expectedNonce || !validNonce(snapshot.ProcessInstanceID) {
		return ErrProtocol
	}
	if validateContext(validation) != nil {
		return ErrProtocol
	}
	if snapshot.SampleSequence > MaxExactJSONInteger || snapshot.ProcessUptimeMS > MaxExactJSONInteger {
		return ErrProtocol
	}
	if validateHandshakes(snapshot.Handshakes) != nil || validatePeers(snapshot.Peers) != nil || validateLighthouses(snapshot.Lighthouses, snapshot.Schema, validation) != nil {
		return ErrProtocol
	}
	if ageExceedsUptime(snapshot.Handshakes.MostRecentCompletionAgeMS, snapshot.ProcessUptimeMS) ||
		ageExceedsUptime(snapshot.Peers.OldestAuthenticatedRXAgeMS, snapshot.ProcessUptimeMS) ||
		ageExceedsUptime(snapshot.Lighthouses.MostRecentAuthenticatedRXAgeMS, snapshot.ProcessUptimeMS) {
		return ErrProtocol
	}
	for _, entry := range snapshot.Lighthouses.Entries {
		if ageExceedsUptime(entry.LastHandshakeAgeMS, snapshot.ProcessUptimeMS) || ageExceedsUptime(entry.LastAuthenticatedRXAgeMS, snapshot.ProcessUptimeMS) {
			return ErrProtocol
		}
	}
	if snapshot.Handshakes.CompletedTotal < snapshot.Peers.Established {
		return ErrProtocol
	}
	if snapshot.Lighthouses.Established > snapshot.Peers.Established ||
		snapshot.Lighthouses.AuthenticatedRXWithin2m > snapshot.Peers.AuthenticatedRXWithin2m ||
		snapshot.Lighthouses.AuthenticatedRXWithin5m > snapshot.Peers.AuthenticatedRXWithin5m {
		return ErrProtocol
	}
	return nil
}

func validateHandshakes(handshakes HandshakeSnapshot) error {
	if handshakes.CompletedTotal > MaxExactJSONInteger || handshakes.TimedOutTotal > MaxExactJSONInteger || handshakes.Pending > MaxAggregateCount {
		return ErrProtocol
	}
	if !validAge(handshakes.MostRecentCompletionAgeMS) {
		return ErrProtocol
	}
	if (handshakes.CompletedTotal == 0) != (handshakes.MostRecentCompletionAgeMS == nil) {
		return ErrProtocol
	}
	return nil
}

func validatePeers(peers PeerSnapshot) error {
	if peers.Established > MaxAggregateCount || peers.AuthenticatedRXWithin2m > MaxAggregateCount || peers.AuthenticatedRXWithin5m > MaxAggregateCount {
		return ErrProtocol
	}
	if peers.AuthenticatedRXWithin2m > peers.AuthenticatedRXWithin5m || peers.AuthenticatedRXWithin5m > peers.Established {
		return ErrProtocol
	}
	if !validAge(peers.OldestAuthenticatedRXAgeMS) {
		return ErrProtocol
	}
	if peers.Established == 0 && peers.OldestAuthenticatedRXAgeMS != nil {
		return ErrProtocol
	}
	if peers.OldestAuthenticatedRXAgeMS == nil && peers.AuthenticatedRXWithin5m != 0 {
		return ErrProtocol
	}
	return nil
}

func validateLighthouses(lighthouses LighthouseSnapshot, schema string, validation ValidationContext) error {
	if lighthouses.Configured > MaxAggregateCount || lighthouses.Established > MaxAggregateCount ||
		lighthouses.AuthenticatedRXWithin2m > MaxAggregateCount || lighthouses.AuthenticatedRXWithin5m > MaxAggregateCount {
		return ErrProtocol
	}
	if lighthouses.Established > lighthouses.Configured ||
		lighthouses.AuthenticatedRXWithin2m > lighthouses.AuthenticatedRXWithin5m ||
		lighthouses.AuthenticatedRXWithin5m > lighthouses.Established {
		return ErrProtocol
	}
	if lighthouses.Configured != uint64(len(validation.lighthouses)) ||
		lighthouses.Overflow != (lighthouses.Configured > MaxLighthouseEntries) ||
		lighthouses.Entries == nil || len(lighthouses.Entries) > MaxLighthouseEntries || uint64(len(lighthouses.Entries)) > lighthouses.Configured {
		return ErrProtocol
	}
	if !validAge(lighthouses.MostRecentAuthenticatedRXAgeMS) ||
		(lighthouses.Configured == 0 && lighthouses.MostRecentAuthenticatedRXAgeMS != nil) {
		return ErrProtocol
	}
	if schema == SnapshotSchemaV1 && lighthouses.MostRecentAuthenticatedRXAgeMS != nil {
		return ErrProtocol
	}

	var previous [4]byte
	havePrevious := false
	var established, recent2m, recent5m uint64
	var mostRecentEntryRXAgeMS *uint64
	for _, entry := range lighthouses.Entries {
		address, err := netip.ParseAddr(entry.VPNIP)
		if err != nil || !address.Is4() || address.String() != entry.VPNIP ||
			!validation.network.Contains(address) || !validation.containsLighthouse(address) {
			return ErrProtocol
		}
		current := address.As4()
		if havePrevious && bytes.Compare(previous[:], current[:]) >= 0 {
			return ErrProtocol
		}
		previous = current
		havePrevious = true

		if !validAge(entry.LastHandshakeAgeMS) || !validAge(entry.LastAuthenticatedRXAgeMS) {
			return ErrProtocol
		}
		if entry.Established && entry.LastHandshakeAgeMS == nil {
			return ErrProtocol
		}
		if entry.LastAuthenticatedRXAgeMS != nil && entry.LastHandshakeAgeMS == nil {
			return ErrProtocol
		}
		if entry.Established {
			established++
		}
		if entry.LastAuthenticatedRXAgeMS != nil {
			if !entry.Established {
				return ErrProtocol
			}
			mostRecentEntryRXAgeMS = minAge(mostRecentEntryRXAgeMS, entry.LastAuthenticatedRXAgeMS)
			if *entry.LastAuthenticatedRXAgeMS <= AuthenticatedRX5mLimit {
				recent5m++
			}
			if *entry.LastAuthenticatedRXAgeMS <= AuthenticatedRX2mLimit {
				recent2m++
			}
		}
	}

	if lighthouses.Overflow {
		if established > lighthouses.Established || recent2m > lighthouses.AuthenticatedRXWithin2m || recent5m > lighthouses.AuthenticatedRXWithin5m {
			return ErrProtocol
		}
	} else if established != lighthouses.Established || recent2m != lighthouses.AuthenticatedRXWithin2m || recent5m != lighthouses.AuthenticatedRXWithin5m {
		return ErrProtocol
	}
	if schema == SnapshotSchemaV2 {
		retained := lighthouses.MostRecentAuthenticatedRXAgeMS
		if (lighthouses.AuthenticatedRXWithin5m > 0 || mostRecentEntryRXAgeMS != nil) && retained == nil {
			return ErrProtocol
		}
		if retained != nil {
			if lighthouses.AuthenticatedRXWithin2m > 0 && *retained > AuthenticatedRX2mLimit {
				return ErrProtocol
			}
			if lighthouses.AuthenticatedRXWithin5m > 0 && *retained > AuthenticatedRX5mLimit {
				return ErrProtocol
			}
			if mostRecentEntryRXAgeMS != nil && *retained > *mostRecentEntryRXAgeMS {
				return ErrProtocol
			}
		}
	}
	return nil
}

func minAge(current, candidate *uint64) *uint64 {
	if candidate == nil {
		return current
	}
	if current == nil || *candidate < *current {
		value := *candidate
		return &value
	}
	return current
}

func validateContext(validation ValidationContext) error {
	if !validation.valid || !validation.network.IsValid() || !validation.network.Addr().Is4() ||
		validation.network != validation.network.Masked() || len(validation.lighthouses) > MaxConfiguredLighthouses {
		return ErrProtocol
	}
	var previous [4]byte
	for index, address := range validation.lighthouses {
		if !address.IsValid() || !address.Is4() || !validation.network.Contains(address) {
			return ErrProtocol
		}
		current := address.As4()
		if index > 0 && bytes.Compare(previous[:], current[:]) >= 0 {
			return ErrProtocol
		}
		previous = current
	}
	return nil
}

func (validation ValidationContext) containsLighthouse(address netip.Addr) bool {
	index := sort.Search(len(validation.lighthouses), func(index int) bool {
		candidateBytes := validation.lighthouses[index].As4()
		addressBytes := address.As4()
		return bytes.Compare(candidateBytes[:], addressBytes[:]) >= 0
	})
	return index < len(validation.lighthouses) && validation.lighthouses[index] == address
}

func ageExceedsUptime(age *uint64, uptime uint64) bool {
	return age != nil && *age > uptime
}

func validAge(age *uint64) bool {
	return age == nil || *age <= MaxAgeMilliseconds
}

func validNonce(value string) bool {
	if len(value) != NonceHexLength {
		return false
	}
	for index := range value {
		character := value[index]
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}

func validLineFrame(message []byte, limit int) bool {
	if len(message) == 0 || len(message) > limit || message[len(message)-1] != '\n' {
		return false
	}
	return !bytes.ContainsAny(message[:len(message)-1], "\r\n")
}

type fieldDecoder struct {
	name   string
	decode func(json.RawMessage) error
}

func decodeObject(raw []byte, fields []fieldDecoder) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return ErrProtocol
	}
	allowed := make(map[string]fieldDecoder, len(fields))
	seen := make(map[string]struct{}, len(fields))
	for _, field := range fields {
		allowed[field.name] = field
	}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return ErrProtocol
		}
		name, ok := token.(string)
		if !ok {
			return ErrProtocol
		}
		field, ok := allowed[name]
		if !ok {
			return ErrProtocol
		}
		if _, duplicate := seen[name]; duplicate {
			return ErrProtocol
		}
		seen[name] = struct{}{}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil || field.decode(value) != nil {
			return ErrProtocol
		}
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') || len(seen) != len(fields) {
		return ErrProtocol
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ErrProtocol
	}
	return nil
}

func stringField(destination *string) func(json.RawMessage) error {
	return func(raw json.RawMessage) error {
		var value string
		if err := json.Unmarshal(raw, &value); err != nil {
			return ErrProtocol
		}
		canonical, err := json.Marshal(value)
		if err != nil || !bytes.Equal(raw, canonical) {
			return ErrProtocol
		}
		*destination = value
		return nil
	}
}

func boundedUintField(destination *uint64, maximum uint64) func(json.RawMessage) error {
	return func(raw json.RawMessage) error {
		value, err := decodeBoundedUint(raw, maximum)
		if err != nil {
			return err
		}
		*destination = value
		return nil
	}
}

func nullableAgeField(destination **uint64) func(json.RawMessage) error {
	return func(raw json.RawMessage) error {
		if bytes.Equal(raw, []byte("null")) {
			*destination = nil
			return nil
		}
		value, err := decodeBoundedUint(raw, MaxAgeMilliseconds)
		if err != nil {
			return err
		}
		*destination = &value
		return nil
	}
}

func boolField(destination *bool) func(json.RawMessage) error {
	return func(raw json.RawMessage) error {
		switch string(raw) {
		case "true":
			*destination = true
		case "false":
			*destination = false
		default:
			return ErrProtocol
		}
		return nil
	}
}

func decodeBoundedUint(raw []byte, maximum uint64) (uint64, error) {
	if len(raw) == 0 || (len(raw) > 1 && raw[0] == '0') {
		return 0, ErrProtocol
	}
	for _, character := range raw {
		if character < '0' || character > '9' {
			return 0, ErrProtocol
		}
	}
	value, err := strconv.ParseUint(string(raw), 10, 64)
	if err != nil || value > maximum {
		return 0, ErrProtocol
	}
	return value, nil
}

func decodeHandshakes(raw json.RawMessage, destination *HandshakeSnapshot) error {
	return decodeObject(raw, []fieldDecoder{
		{name: "completed_total", decode: boundedUintField(&destination.CompletedTotal, MaxExactJSONInteger)},
		{name: "timed_out_total", decode: boundedUintField(&destination.TimedOutTotal, MaxExactJSONInteger)},
		{name: "pending", decode: boundedUintField(&destination.Pending, MaxAggregateCount)},
		{name: "most_recent_completion_age_ms", decode: nullableAgeField(&destination.MostRecentCompletionAgeMS)},
	})
}

func decodePeers(raw json.RawMessage, destination *PeerSnapshot) error {
	return decodeObject(raw, []fieldDecoder{
		{name: "established", decode: boundedUintField(&destination.Established, MaxAggregateCount)},
		{name: "authenticated_rx_within_2m", decode: boundedUintField(&destination.AuthenticatedRXWithin2m, MaxAggregateCount)},
		{name: "authenticated_rx_within_5m", decode: boundedUintField(&destination.AuthenticatedRXWithin5m, MaxAggregateCount)},
		{name: "oldest_authenticated_rx_age_ms", decode: nullableAgeField(&destination.OldestAuthenticatedRXAgeMS)},
	})
}

func decodeLighthouses(raw json.RawMessage, destination *LighthouseSnapshot) error {
	return decodeObject(raw, []fieldDecoder{
		{name: "configured", decode: boundedUintField(&destination.Configured, MaxAggregateCount)},
		{name: "established", decode: boundedUintField(&destination.Established, MaxAggregateCount)},
		{name: "authenticated_rx_within_2m", decode: boundedUintField(&destination.AuthenticatedRXWithin2m, MaxAggregateCount)},
		{name: "authenticated_rx_within_5m", decode: boundedUintField(&destination.AuthenticatedRXWithin5m, MaxAggregateCount)},
		{name: "most_recent_authenticated_rx_age_ms", decode: nullableAgeField(&destination.MostRecentAuthenticatedRXAgeMS)},
		{name: "overflow", decode: boolField(&destination.Overflow)},
		{name: "entries", decode: func(raw json.RawMessage) error { return decodeLighthouseEntries(raw, &destination.Entries) }},
	})
}

func decodeLighthousesV1(raw json.RawMessage, destination *lighthouseSnapshotV1) error {
	return decodeObject(raw, []fieldDecoder{
		{name: "configured", decode: boundedUintField(&destination.Configured, MaxAggregateCount)},
		{name: "established", decode: boundedUintField(&destination.Established, MaxAggregateCount)},
		{name: "authenticated_rx_within_2m", decode: boundedUintField(&destination.AuthenticatedRXWithin2m, MaxAggregateCount)},
		{name: "authenticated_rx_within_5m", decode: boundedUintField(&destination.AuthenticatedRXWithin5m, MaxAggregateCount)},
		{name: "overflow", decode: boolField(&destination.Overflow)},
		{name: "entries", decode: func(raw json.RawMessage) error { return decodeLighthouseEntries(raw, &destination.Entries) }},
	})
}

func decodeLighthouseEntries(raw json.RawMessage, destination *[]LighthouseEntry) error {
	if len(raw) == 0 || raw[0] != '[' {
		return ErrProtocol
	}
	var entries []json.RawMessage
	if err := json.Unmarshal(raw, &entries); err != nil || len(entries) > MaxLighthouseEntries {
		return ErrProtocol
	}
	decoded := make([]LighthouseEntry, len(entries))
	for index := range entries {
		if decodeObject(entries[index], []fieldDecoder{
			{name: "vpn_ip", decode: stringField(&decoded[index].VPNIP)},
			{name: "established", decode: boolField(&decoded[index].Established)},
			{name: "last_handshake_age_ms", decode: nullableAgeField(&decoded[index].LastHandshakeAgeMS)},
			{name: "last_authenticated_rx_age_ms", decode: nullableAgeField(&decoded[index].LastAuthenticatedRXAgeMS)},
		}) != nil {
			return ErrProtocol
		}
	}
	*destination = decoded
	return nil
}
