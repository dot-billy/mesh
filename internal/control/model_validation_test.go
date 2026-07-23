package control

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"mesh/internal/postgresstore"
)

func TestCreateNodeCanonicalGroupBoundaryAndEndpointBoundary(t *testing.T) {
	service := testServiceWithIssuer(t, &countingIssuer{})
	network, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "bounded", CIDR: "10.90.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	groups := make([]string, 0, maxNodeGroups-1)
	for index := 0; index < maxNodeGroups-1; index++ {
		groups = append(groups, fmt.Sprintf("g%02d", index))
	}
	host := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	if len(host) != maxPublicEndpointHostBytes {
		t.Fatalf("test host length=%d", len(host))
	}
	created, err := service.CreateNode(network.ID, CreateNodeInput{
		Name: "boundary-node", Role: "lighthouse", PublicEndpoint: host + ":65535", Groups: groups,
	})
	if err != nil {
		t.Fatalf("create boundary node: %v", err)
	}
	if len(created.Node.Groups) != maxNodeGroups || created.Node.Groups[0] != "all" || !validCanonicalNodeGroups(created.Node.Groups) {
		t.Fatalf("created groups are not canonical at the boundary: %#v", created.Node.Groups)
	}
	if err := validateEndpoint("[2001:db8::1]:4242"); err != nil {
		t.Fatalf("canonical IPv6 endpoint rejected: %v", err)
	}
}

func TestCreateNodeRejectsUnsafeInputBeforePersistence(t *testing.T) {
	tooManyGroups := make([]string, maxNodeGroups+1)
	for index := range tooManyGroups {
		tooManyGroups[index] = fmt.Sprintf("group%02d", index)
	}
	tests := []struct {
		name  string
		input CreateNodeInput
	}{
		{name: "too many groups", input: CreateNodeInput{Name: "node-01", Groups: tooManyGroups}},
		{name: "invalid group", input: CreateNodeInput{Name: "node-01", Groups: []string{"valid", "not valid"}}},
		{name: "oversized endpoint host", input: CreateNodeInput{Name: "node-01", Role: "lighthouse", PublicEndpoint: strings.Repeat("a", maxPublicEndpointHostBytes+1) + ":4242"}},
		{name: "oversized DNS label", input: CreateNodeInput{Name: "node-01", Role: "lighthouse", PublicEndpoint: strings.Repeat("a", 64) + ".example:4242"}},
		{name: "nonnumeric port", input: CreateNodeInput{Name: "node-01", Role: "lighthouse", PublicEndpoint: "vpn.example.com:http"}},
		{name: "signed numeric port", input: CreateNodeInput{Name: "node-01", Role: "lighthouse", PublicEndpoint: "vpn.example.com:+4242"}},
		{name: "control character", input: CreateNodeInput{Name: "node-01", Role: "lighthouse", PublicEndpoint: "vpn.example.com\n:4242"}},
		{name: "invalid UTF-8", input: CreateNodeInput{Name: "node-01", Role: "lighthouse", PublicEndpoint: string([]byte{0xff}) + ":4242"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			backend := &fakeStateStore{state: State{Version: 1}}
			service, err := NewServiceWithStateStore(backend, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := service.CreateNode("network", test.input); !errors.Is(err, ErrInvalid) {
				t.Fatalf("CreateNode() error=%v, want invalid input", err)
			}
			if backend.viewCalls != 0 || backend.updateCalls != 0 || backend.updateCallbackRuns != 0 {
				t.Fatalf("invalid input touched persistence: views=%d updates=%d callbacks=%d", backend.viewCalls, backend.updateCalls, backend.updateCallbackRuns)
			}
		})
	}
}

func TestStateGraphAcceptsFieldBoundariesAndCurrentAuditShapes(t *testing.T) {
	service, state := boundedControlState(t)
	state.Networks[0].CACertificate = strings.Repeat("c", maxNebulaCACertificateSize)
	state.Networks[0].EncryptedCAKey = base64.RawURLEncoding.EncodeToString(make([]byte, maxNebulaCAPrivateKeySize+secretBoxNonceBytes+secretBoxTagBytes))
	state.Nodes[0].Certificate = strings.Repeat("n", maxNebulaHostCertificateSize)
	state.Revocations = append(state.Revocations, CertificateRevocation{
		Fingerprint: strings.Repeat("a", 64), NodeID: state.Nodes[0].ID, NetworkID: state.Networks[0].ID,
		Reason: strings.Repeat("r", maxRevocationReasonBytes), At: service.now(),
	})
	state.Audit[0].Action = strings.Repeat("a", maxAuditActionBytes)
	state.Audit[0].Resource = strings.Repeat("r", maxAuditResourceBytes)
	state.Audit[0].Details = map[string]any{
		"string": strings.Repeat("s", maxAuditDetailStringBytes),
		"bool":   true,
		"int":    int64(42),
		"float":  float64(42),
		"time":   service.now(),
		"nested": map[string]any{"list": []any{"value", false, nil}},
	}
	if err := validateStateGraph(state); err != nil {
		t.Fatalf("valid field boundaries rejected: %v", err)
	}
}

func TestStateGraphRejectsUnboundedAndNoncanonicalFields(t *testing.T) {
	_, baseline := boundedControlState(t)
	tests := []struct {
		name    string
		mutate  func(*State)
		message string
	}{
		{name: "unsorted groups", mutate: func(state *State) { state.Nodes[0].Groups = []string{"operators", "all"} }, message: "non-canonical certificate groups"},
		{name: "duplicate groups", mutate: func(state *State) { state.Nodes[0].Groups = []string{"all", "all"} }, message: "non-canonical certificate groups"},
		{name: "too many groups", mutate: func(state *State) {
			state.Nodes[0].Groups = make([]string, maxNodeGroups+1)
			for index := range state.Nodes[0].Groups {
				state.Nodes[0].Groups[index] = fmt.Sprintf("g%02d", index)
			}
			state.Nodes[0].Groups[0] = "all"
		}, message: "non-canonical certificate groups"},
		{name: "unsafe endpoint", mutate: func(state *State) { state.Nodes[0].PublicEndpoint = "vpn.example.com:+42" }, message: "public endpoint"},
		{name: "oversized CA certificate", mutate: func(state *State) {
			state.Networks[0].CACertificate = strings.Repeat("c", maxNebulaCACertificateSize+1)
		}, message: "CA certificate"},
		{name: "invalid UTF-8 CA certificate", mutate: func(state *State) { state.Networks[0].CACertificate = string([]byte{0xff}) }, message: "CA certificate"},
		{name: "oversized encrypted CA key", mutate: func(state *State) { state.Networks[0].EncryptedCAKey = strings.Repeat("A", maxEncryptedCAKeyBytes+1) }, message: "encrypted CA key"},
		{name: "noncanonical signing public key", mutate: func(state *State) { state.Networks[0].ConfigSigningPublicKey += "=" }, message: "signing public key"},
		{name: "wrong signing private ciphertext size", mutate: func(state *State) {
			state.Networks[0].EncryptedConfigSigningKey = base64.RawURLEncoding.EncodeToString(make([]byte, 91))
		}, message: "encrypted config signing key"},
		{name: "oversized host certificate", mutate: func(state *State) { state.Nodes[0].Certificate = strings.Repeat("n", maxNebulaHostCertificateSize+1) }, message: "certificate"},
		{name: "oversized enrollment claim ID", mutate: func(state *State) {
			claimedAt := time.Now().UTC()
			state.Enrollments[0].ClaimID = strings.Repeat("c", 129)
			state.Enrollments[0].ClaimedAt = &claimedAt
			state.Enrollments[0].ClaimKeyHash = HashToken("bounded-enrollment-claim")
		}, message: "enrollment"},
		{name: "oversized enrollment claim key", mutate: func(state *State) {
			claimedAt := time.Now().UTC()
			state.Enrollments[0].ClaimID = "claim_01"
			state.Enrollments[0].ClaimedAt = &claimedAt
			state.Enrollments[0].ClaimKeyHash = strings.Repeat("a", 65)
		}, message: "enrollment"},
		{name: "oversized renewal claim ID", mutate: func(state *State) {
			claimedAt := time.Now().UTC()
			state.Nodes[0].RenewalClaimID = strings.Repeat("r", 129)
			state.Nodes[0].RenewalClaimedAt = &claimedAt
		}, message: "renewal claim"},
		{name: "incomplete renewal claim", mutate: func(state *State) { state.Nodes[0].RenewalClaimID = "renewal_01" }, message: "renewal claim"},
		{name: "oversized revocation reason", mutate: func(state *State) {
			state.Revocations = []CertificateRevocation{{Fingerprint: strings.Repeat("a", 64), NodeID: state.Nodes[0].ID, NetworkID: state.Networks[0].ID, Reason: strings.Repeat("r", maxRevocationReasonBytes+1), At: time.Now().UTC()}}
		}, message: "unsafe reason"},
		{name: "control in revocation reason", mutate: func(state *State) {
			state.Revocations = []CertificateRevocation{{Fingerprint: strings.Repeat("a", 64), NodeID: state.Nodes[0].ID, NetworkID: state.Networks[0].ID, Reason: "operator\ninput", At: time.Now().UTC()}}
		}, message: "unsafe reason"},
		{name: "oversized audit action", mutate: func(state *State) { state.Audit[0].Action = strings.Repeat("a", maxAuditActionBytes+1) }, message: "invalid metadata"},
		{name: "unsafe audit resource", mutate: func(state *State) { state.Audit[0].Resource = "network\nsecret" }, message: "invalid metadata"},
		{name: "too many detail keys", mutate: func(state *State) {
			state.Audit[0].Details = make(map[string]any, maxAuditDetailKeysPerObject+1)
			for index := 0; index <= maxAuditDetailKeysPerObject; index++ {
				state.Audit[0].Details[fmt.Sprintf("key_%02d", index)] = index
			}
		}, message: "exceeds 32 keys"},
		{name: "unsafe detail key", mutate: func(state *State) { state.Audit[0].Details = map[string]any{"unsafe key": true} }, message: "detail key"},
		{name: "oversized detail string", mutate: func(state *State) {
			state.Audit[0].Details = map[string]any{"value": strings.Repeat("v", maxAuditDetailStringBytes+1)}
		}, message: "string is oversized"},
		{name: "control in detail string", mutate: func(state *State) { state.Audit[0].Details = map[string]any{"value": "unsafe\nvalue"} }, message: "control characters"},
		{name: "excess detail depth", mutate: func(state *State) {
			state.Audit[0].Details = map[string]any{"one": map[string]any{"two": map[string]any{"three": map[string]any{"four": "too deep"}}}}
		}, message: "nesting exceeds"},
		{name: "unsupported detail type", mutate: func(state *State) { state.Audit[0].Details = map[string]any{"value": []string{"unsupported"}} }, message: "unsupported detail type"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state, err := cloneState(baseline)
			if err != nil {
				t.Fatal(err)
			}
			test.mutate(&state)
			if err := validateStateGraph(state); err == nil || !strings.Contains(err.Error(), test.message) {
				t.Fatalf("invalid state returned %v, want message containing %q", err, test.message)
			}
		})
	}
}

func TestBoundedGraphFailsClosedAcrossFilePostgresAndRecovery(t *testing.T) {
	service, state := boundedControlState(t)
	state.Nodes[0].Groups = []string{"operators", "all"}
	raw, err := encodePersistedState(state)
	if err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if store, err := OpenStore(path); err == nil {
		_ = store.Close()
		t.Fatal("file store accepted non-canonical groups")
	}
	if _, err := decodeValidPostgresControlState(raw); !errors.Is(err, postgresstore.ErrCorruptDocument) {
		t.Fatalf("PostgreSQL adapter error=%v, want corrupt document", err)
	}
	if err := ValidateRecoverySnapshot(raw, service.box); err == nil || !strings.Contains(err.Error(), "non-canonical certificate groups") {
		t.Fatalf("recovery accepted invalid graph: %v", err)
	}
}

func TestStateGraphBoundsPersistedRecoveryResultMaterial(t *testing.T) {
	_, baseline := boundedRecoveryResultState(t)
	tests := []struct {
		name    string
		mutate  func(*AgentRecoveryBundle)
		message string
	}{
		{name: "noncanonical groups", mutate: func(result *AgentRecoveryBundle) { result.Node.Groups = []string{"operators", "all"} }, message: "groups are not canonical"},
		{name: "unsafe endpoint", mutate: func(result *AgentRecoveryBundle) { result.Node.PublicEndpoint = "vpn.example.com:+42" }, message: "node endpoint"},
		{name: "oversized embedded node name", mutate: func(result *AgentRecoveryBundle) { result.Node.Name = strings.Repeat("n", 64) }, message: "node metadata"},
		{name: "oversized embedded node address", mutate: func(result *AgentRecoveryBundle) { result.Node.IP = strings.Repeat("1", 1<<20) }, message: "node address"},
		{name: "oversized embedded node telemetry", mutate: func(result *AgentRecoveryBundle) {
			result.Node.LastError = strings.Repeat("e", maxPersistedLastErrorBytes+1)
		}, message: "node telemetry"},
		{name: "mismatched embedded credential lifecycle", mutate: func(result *AgentRecoveryBundle) {
			result.Node.AgentCredentialGeneration++
		}, message: "node lifecycle"},
		{name: "oversized embedded node certificate", mutate: func(result *AgentRecoveryBundle) {
			result.Node.Certificate = strings.Repeat("n", maxNebulaHostCertificateSize+1)
		}, message: "result certificate"},
		{name: "oversized response certificate", mutate: func(result *AgentRecoveryBundle) {
			result.Certificate = strings.Repeat("n", maxNebulaHostCertificateSize+1)
		}, message: "result certificate"},
		{name: "oversized response CA", mutate: func(result *AgentRecoveryBundle) { result.CA = strings.Repeat("c", maxNebulaCACertificateSize+1) }, message: "result CA certificate"},
		{name: "oversized managed config", mutate: func(result *AgentRecoveryBundle) { result.Config = strings.Repeat("c", MaxManagedConfigBytes+1) }, message: "managed config"},
		{name: "carriage return in managed config", mutate: func(result *AgentRecoveryBundle) { result.Config = "config: invalid\r\n" }, message: "managed config"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state, err := cloneState(baseline)
			if err != nil {
				t.Fatal(err)
			}
			test.mutate(state.AgentRecoveries[0].Result)
			if err := validateStateGraph(state); err == nil || !strings.Contains(err.Error(), test.message) {
				t.Fatalf("invalid recovery result returned %v, want %q", err, test.message)
			}
		})
	}

	state, err := cloneState(baseline)
	if err != nil {
		t.Fatal(err)
	}
	state.AgentRecoveries[0].Result.ConfigSigningPublicKey += "="
	if err := validatePersistedRecoveryResultMaterial(state.AgentRecoveries[0].Result, state.Networks[0]); err == nil || !strings.Contains(err.Error(), "signing public key") {
		t.Fatalf("noncanonical recovery signing key returned %v", err)
	}
}

func TestOversizedEnrollmentClaimFailsBeforePersistenceAndAtRecoveryBoundaries(t *testing.T) {
	service, baseline := boundedControlState(t)
	before, err := os.ReadFile(service.store.path)
	if err != nil {
		t.Fatal(err)
	}
	mutate := func(state *State) {
		claimedAt := time.Now().UTC()
		state.Enrollments[0].ClaimID = strings.Repeat("c", 129)
		state.Enrollments[0].ClaimedAt = &claimedAt
		state.Enrollments[0].ClaimKeyHash = HashToken("bounded-enrollment-claim")
	}
	err = service.store.Update(func(state *State) error {
		mutate(state)
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "claim metadata") {
		t.Fatalf("oversized enrollment claim mutation returned %v", err)
	}
	after, err := os.ReadFile(service.store.path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("rejected enrollment claim mutation changed persisted bytes")
	}

	mutate(&baseline)
	raw, err := encodePersistedState(baseline)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeValidPostgresControlState(raw); !errors.Is(err, postgresstore.ErrCorruptDocument) || !strings.Contains(err.Error(), "claim metadata") {
		t.Fatalf("PostgreSQL enrollment claim error=%v, want corrupt bounded claim", err)
	}
	if err := ValidateRecoverySnapshot(raw, service.box); err == nil || !strings.Contains(err.Error(), "claim metadata") {
		t.Fatalf("offline recovery accepted oversized enrollment claim: %v", err)
	}
}

func TestOversizedRecoveryConfigFailsBeforePersistenceAndAtRecoveryBoundaries(t *testing.T) {
	service, baseline := boundedRecoveryResultState(t)
	before, err := os.ReadFile(service.store.path)
	if err != nil {
		t.Fatal(err)
	}
	err = service.store.Update(func(state *State) error {
		state.AgentRecoveries[0].Result.Config = strings.Repeat("c", MaxManagedConfigBytes+1)
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "managed config") {
		t.Fatalf("oversized recovery config mutation returned %v", err)
	}
	after, err := os.ReadFile(service.store.path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("rejected recovery config mutation changed persisted bytes")
	}

	baseline.AgentRecoveries[0].Result.Config = strings.Repeat("c", MaxManagedConfigBytes+1)
	raw, err := encodePersistedState(baseline)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeValidPostgresControlState(raw); !errors.Is(err, postgresstore.ErrCorruptDocument) || !strings.Contains(err.Error(), "managed config") {
		t.Fatalf("PostgreSQL recovery config error=%v, want corrupt bounded config", err)
	}
	if err := ValidateRecoverySnapshot(raw, service.box); err == nil || !strings.Contains(err.Error(), "managed config") {
		t.Fatalf("offline recovery accepted oversized managed config: %v", err)
	}
}

func TestCloneStateDeepCopiesStructuredAuditDetails(t *testing.T) {
	original := State{Audit: []AuditEvent{{Details: map[string]any{
		"object": map[string]any{"value": "original"},
		"array":  []any{map[string]any{"value": "original"}},
	}}}}
	cloned, err := cloneState(original)
	if err != nil {
		t.Fatal(err)
	}
	cloned.Audit[0].Details["object"].(map[string]any)["value"] = "changed"
	cloned.Audit[0].Details["array"].([]any)[0].(map[string]any)["value"] = "changed"
	if original.Audit[0].Details["object"].(map[string]any)["value"] != "original" || original.Audit[0].Details["array"].([]any)[0].(map[string]any)["value"] != "original" {
		t.Fatal("structured audit details remained aliased after clone")
	}
}

func boundedControlState(t *testing.T) (*Service, State) {
	t.Helper()
	service := testServiceWithIssuer(t, &countingIssuer{})
	network, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "graph", CIDR: "10.91.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.CreateNode(network.ID, CreateNodeInput{Name: "node-01", Groups: []string{"operators"}}); err != nil {
		t.Fatal(err)
	}
	var state State
	if err := service.store.View(func(snapshot State) error { state = snapshot; return nil }); err != nil {
		t.Fatal(err)
	}
	return service, state
}

func boundedRecoveryResultState(t *testing.T) (*Service, State) {
	t.Helper()
	now := time.Date(2026, 7, 20, 4, 0, 0, 0, time.UTC)
	issuer := &countingIssuer{now: func() time.Time { return now }}
	service := testServiceWithIssuer(t, issuer)
	service.now = func() time.Time { return now }
	network, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "recovery-bounds", CIDR: "10.92.0.0/24", CertificateTTL: 24})
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.CreateNode(network.ID, CreateNodeInput{Name: "recoverable", Groups: []string{"operators"}})
	if err != nil {
		t.Fatal(err)
	}
	publicKey := testNebulaPublicKey('B')
	if _, err := service.Enroll(context.Background(), created.EnrollmentToken, publicKey, HashToken(strings.Repeat("a", 42)+"A")); err != nil {
		t.Fatal(err)
	}
	issued, err := service.IssueAgentRecovery(created.Node.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.RecoverAgent(issued.RecoveryToken, publicKey, HashToken(strings.Repeat("b", 42)+"A")); err != nil {
		t.Fatal(err)
	}
	var state State
	if err := service.store.View(func(snapshot State) error { state = snapshot; return nil }); err != nil {
		t.Fatal(err)
	}
	if len(state.AgentRecoveries) != 1 || state.AgentRecoveries[0].Result == nil {
		t.Fatalf("missing committed recovery result: %#v", state.AgentRecoveries)
	}
	return service, state
}
