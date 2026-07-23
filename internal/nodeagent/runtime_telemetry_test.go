package nodeagent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	nebulacert "github.com/slackhq/nebula/cert"
	nebulacerttest "github.com/slackhq/nebula/cert_test"

	"mesh/internal/control"
	"mesh/internal/runtimeobserver"
	"mesh/internal/runtimetelemetry"
)

func attemptedRuntimeTelemetryProbeResult() runtimetelemetry.ActiveProbeResult {
	age := uint64(0)
	return runtimetelemetry.ActiveProbeResult{
		Version: runtimetelemetry.ActiveProbeVersionV1, State: runtimetelemetry.ProbeAttempted,
		SampleAgeMS: &age, Attempted: 1, Replied: 1, DurationMS: 3,
	}
}

type recordingRouteOverlapInspector struct {
	result runtimetelemetry.RouteOverlapResult
	calls  int
}

func (*recordingRouteOverlapInspector) Supported() bool { return true }

func (inspector *recordingRouteOverlapInspector) Inspect(context.Context, verifiedRuntimeTopology) runtimetelemetry.RouteOverlapResult {
	inspector.calls++
	return runtimetelemetry.CloneRouteOverlap(inspector.result)
}

func TestObserveVerifiedRuntimeTelemetryMapsOnlyBoundedAggregates(t *testing.T) {
	bundle := runtimeTelemetryBundle(t, []netip.Prefix{netip.MustParsePrefix("10.42.0.9/24")}, runtimeTelemetryConfig("10.42.0.1", "10.42.0.2"))
	snapshot := validRuntimeObserverSnapshot()
	observer := &validatingRuntimeObserver{snapshot: snapshot}

	got := observeVerifiedRuntimeTelemetry(context.Background(), bundle, observer)
	if observer.calls != 1 {
		t.Fatalf("observer calls = %d, want 1", observer.calls)
	}
	want := RuntimeTelemetryObservation{
		Version: RuntimeTelemetryObservationVersionV2,
		State:   RuntimeTelemetryObserved,
		Snapshot: &RuntimeTelemetrySnapshot{
			ProcessInstanceID: snapshot.ProcessInstanceID,
			SampleSequence:    snapshot.SampleSequence, ProcessUptimeMS: snapshot.ProcessUptimeMS,
			Handshakes: RuntimeHandshakeTelemetry{CompletedTotal: 3, TimedOutTotal: 1, Pending: 1, MostRecentCompletionAgeMS: snapshot.Handshakes.MostRecentCompletionAgeMS},
			Peers:      RuntimePeerTelemetry{Established: 2, AuthenticatedRXWithin2m: 1, AuthenticatedRXWithin5m: 2, OldestAuthenticatedRXAgeMS: snapshot.Peers.OldestAuthenticatedRXAgeMS},
			Lighthouses: RuntimeLighthouseTelemetry{
				Configured: 2, Established: 2, AuthenticatedRXWithin2m: 1, AuthenticatedRXWithin5m: 2,
				MostRecentAuthenticatedRXAgeMS: snapshot.Lighthouses.MostRecentAuthenticatedRXAgeMS,
			},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("observation = %#v, want %#v", got, want)
	}
}

func TestObserveVerifiedRuntimeTelemetryPreservesLegacyObserverVersion(t *testing.T) {
	bundle := runtimeTelemetryBundle(t, []netip.Prefix{netip.MustParsePrefix("10.42.0.9/24")}, runtimeTelemetryConfig("10.42.0.1", "10.42.0.2"))
	snapshot := validRuntimeObserverSnapshot()
	snapshot.Schema = runtimeobserver.SnapshotSchemaV1
	snapshot.Lighthouses.MostRecentAuthenticatedRXAgeMS = nil

	got := observeVerifiedRuntimeTelemetry(context.Background(), bundle, &validatingRuntimeObserver{snapshot: snapshot})
	if got.Version != RuntimeTelemetryObservationVersionV1 || got.State != RuntimeTelemetryObserved || got.Snapshot == nil ||
		got.Snapshot.Lighthouses.MostRecentAuthenticatedRXAgeMS != nil {
		t.Fatalf("legacy observer version was not preserved: %#v", got)
	}
}

func TestAgentRuntimeTelemetryObservationAndReportStaySeparateFromLifecycleState(t *testing.T) {
	config := activeProbeConfig(
		[]string{"10.42.0.1", "10.42.0.2"},
		[]string{"10.42.0.1", "10.42.0.2"},
		[]string{probeFirewallRule("icmp", "host: any")},
		nil,
	)
	host := runtimeTelemetryBundle(t, []netip.Prefix{netip.MustParsePrefix("10.42.0.9/24")}, config)
	certificate, _, err := nebulacert.UnmarshalCertificateFromPEM([]byte(host.Certificate))
	if err != nil {
		t.Fatal(err)
	}
	signer := newTestSigner(t)
	bundle := signer.bundle(t, 1, config, host.Certificate)
	bundle = signer.resignBundle(t, bundle, func(bundle *Bundle) {
		bundle.Certificate = host.Certificate
		bundle.CertificateFingerprint = host.CertificateFingerprint
		bundle.CertificateExpiresAt = certificate.NotAfter().UTC()
		bundle.CertificateRenewAfter = certificate.NotAfter().UTC().Add(-time.Minute)
	})

	controlRequests := 0
	var reports []runtimetelemetry.ReportInput
	var reportBodies [][]byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/api/v1/agent/runtime-telemetry" {
			if request.Method != http.MethodPost || request.Header.Get("Authorization") == "" {
				t.Errorf("invalid runtime telemetry request method=%s authorization=%q", request.Method, request.Header.Get("Authorization"))
			}
			raw, err := io.ReadAll(request.Body)
			if err != nil {
				t.Errorf("read runtime telemetry report: %v", err)
			}
			var input runtimetelemetry.ReportInput
			if err := json.Unmarshal(raw, &input); err != nil {
				t.Errorf("decode runtime telemetry report: %v", err)
			}
			reportBodies = append(reportBodies, raw)
			reports = append(reports, input)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		controlRequests++
		http.Error(w, "unexpected control request", http.StatusInternalServerError)
	}))
	defer server.Close()
	directory := t.TempDir()
	store, err := NewStateStore(filepath.Join(directory, "agent.json"))
	if err != nil {
		t.Fatal(err)
	}
	bearer, err := GenerateBearer()
	if err != nil {
		t.Fatal(err)
	}
	enrollment := enrollmentBundleFor(bundle, signer, bundle.Certificate)
	state, err := NewEnrollmentState(server.URL, bearer, filepath.Join(directory, "nebula"), bundle.PublicKey, enrollment)
	if err != nil {
		t.Fatal(err)
	}
	observer := &validatingRuntimeObserver{snapshot: validRuntimeObserverSnapshot()}
	probeNow := time.Date(2026, 7, 20, 20, 30, 0, 0, time.UTC)
	probeExecutor := &reportingActiveProbeExecutor{supported: true, result: attemptedRuntimeTelemetryProbeResult()}
	routeInspector := &recordingRouteOverlapInspector{result: runtimetelemetry.ObservedRouteOverlap(false)}
	agent := &Agent{
		Store: store, HTTPClient: server.Client(), Validator: BundleValidator{Runner: realCertificateMetadataRunner{}},
		Reloader: &fakeReloader{}, AgentVersion: "runtime-adapter-test", RuntimeObserver: observer,
		Now: func() time.Time { return probeNow }, activeProbeExecutor: probeExecutor, routeOverlapInspector: routeInspector,
	}
	defer agent.Close()
	if err := agent.InstallEnrollment(context.Background(), state, enrollment, bundle.PrivateKey, bundle.PublicKey); err != nil {
		t.Fatalf("install verified bundle: %v", err)
	}
	before, err := os.ReadFile(store.Path())
	if err != nil {
		t.Fatal(err)
	}
	result := agent.ObserveRuntimeTelemetry(context.Background())
	after, err := os.ReadFile(store.Path())
	if err != nil {
		t.Fatal(err)
	}
	if result.State != RuntimeTelemetryObserved || result.Snapshot == nil || observer.calls != 1 {
		t.Fatalf("observation=%#v calls=%d", result, observer.calls)
	}
	if !bytes.Equal(after, before) {
		t.Fatal("ephemeral runtime observation changed durable agent state")
	}
	if controlRequests != 0 {
		t.Fatalf("ephemeral runtime observation made %d control request(s)", controlRequests)
	}
	if probeExecutor.calls != 0 {
		t.Fatalf("passive ObserveRuntimeTelemetry invoked active probe %d time(s)", probeExecutor.calls)
	}
	if _, exists := reflect.TypeOf(control.HeartbeatInput{}).FieldByName("RuntimeTelemetry"); exists {
		t.Fatal("runtime telemetry was added to the schema-v2 heartbeat contract")
	}

	persisted, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	persisted.HeartbeatSequence = 7
	if err := store.Save(persisted); err != nil {
		t.Fatal(err)
	}
	beforeReport, err := os.ReadFile(store.Path())
	if err != nil {
		t.Fatal(err)
	}
	if err := agent.ReportRuntimeTelemetry(context.Background(), 7); err != nil {
		t.Fatal(err)
	}
	afterReport, err := os.ReadFile(store.Path())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(beforeReport, afterReport) {
		t.Fatal("runtime telemetry report changed durable agent lifecycle state")
	}
	if len(reports) != 1 || reports[0].HeartbeatSequence != 7 || reports[0].Observation.State != runtimetelemetry.StateObserved || reports[0].Observation.Snapshot == nil ||
		reports[0].ActiveProbe == nil || reports[0].ActiveProbe.State != runtimetelemetry.ProbeAttempted || reports[0].ActiveProbe.Replied != 1 ||
		reports[0].RouteOverlap == nil || reports[0].RouteOverlap.State != runtimetelemetry.RouteOverlapObserved || reports[0].RouteOverlap.Overlap ||
		reports[0].EndpointDNS == nil || reports[0].EndpointDNS.State != runtimetelemetry.EndpointDNSObserved || reports[0].EndpointDNS.DNSNames != 0 || reports[0].EndpointDNS.ResolvedNames != 0 {
		t.Fatalf("observed report = %#v", reports)
	}
	if len(reportBodies) != 1 || !bytes.Contains(reportBodies[0], []byte(`"active_probe":{"version":1,"state":"attempted","sample_age_ms":0,"attempted":1,"replied":1,"duration_ms":3}`)) ||
		!bytes.Contains(reportBodies[0], []byte(`"route_overlap":{"version":1,"state":"observed","sample_age_ms":0,"overlap":false}`)) ||
		!bytes.Contains(reportBodies[0], []byte(`"endpoint_dns":{"version":1,"state":"observed","sample_age_ms":0,"dns_names":0,"resolved_names":0}`)) {
		t.Fatalf("outgoing report lacks exact active-probe object: %s", reportBodies[0])
	}
	if probeExecutor.calls != 1 {
		t.Fatalf("active probe calls after first report = %d", probeExecutor.calls)
	}
	if routeInspector.calls != 1 {
		t.Fatalf("route inspector calls after first report = %d", routeInspector.calls)
	}
	if observer.calls != 2 {
		t.Fatalf("observer calls after report = %d, want one new sample", observer.calls)
	}

	observer.err = errors.New("observer unavailable")
	persisted.HeartbeatSequence = 8
	if err := store.Save(persisted); err != nil {
		t.Fatal(err)
	}
	if err := agent.ReportRuntimeTelemetry(context.Background(), 8); err != nil {
		t.Fatal(err)
	}
	if len(reports) != 2 || reports[1].HeartbeatSequence != 8 || reports[1].Observation.State != runtimetelemetry.StateUnknown || reports[1].Observation.Snapshot != nil ||
		reports[1].ActiveProbe == nil || reports[1].ActiveProbe.State != runtimetelemetry.ProbeAttempted || probeExecutor.calls != 1 ||
		reports[1].RouteOverlap == nil || reports[1].RouteOverlap.State != runtimetelemetry.RouteOverlapObserved || routeInspector.calls != 2 ||
		reports[1].EndpointDNS == nil || reports[1].EndpointDNS.State != runtimetelemetry.EndpointDNSObserved {
		t.Fatalf("failed observer report = %#v", reports)
	}

	observer.err = nil
	probeNow = probeNow.Add(activeProbeCadence)
	probeExecutor.result = runtimetelemetry.UnavailableActiveProbe()
	persisted.HeartbeatSequence = 9
	if err := store.Save(persisted); err != nil {
		t.Fatal(err)
	}
	if err := agent.ReportRuntimeTelemetry(context.Background(), 9); err != nil {
		t.Fatal(err)
	}
	if len(reports) != 3 || reports[2].Observation.State != runtimetelemetry.StateObserved || reports[2].Observation.Snapshot == nil ||
		reports[2].ActiveProbe == nil || reports[2].ActiveProbe.State != runtimetelemetry.ProbeUnavailable || probeExecutor.calls != 2 ||
		reports[2].RouteOverlap == nil || reports[2].RouteOverlap.State != runtimetelemetry.RouteOverlapObserved || routeInspector.calls != 3 ||
		reports[2].EndpointDNS == nil || reports[2].EndpointDNS.State != runtimetelemetry.EndpointDNSObserved {
		t.Fatalf("failed probe report = %#v calls=%d", reports, probeExecutor.calls)
	}
	if err := agent.ReportRuntimeTelemetry(context.Background(), 7); !errors.Is(err, runtimetelemetry.ErrConflict) {
		t.Fatalf("stale local heartbeat report error = %v", err)
	}
	if len(reports) != 3 {
		t.Fatal("stale local heartbeat reached the telemetry endpoint")
	}
}

type reportingActiveProbeExecutor struct {
	supported bool
	result    runtimetelemetry.ActiveProbeResult
	calls     int
}

func (executor *reportingActiveProbeExecutor) Supported() bool { return executor.supported }

func (executor *reportingActiveProbeExecutor) Probe(context.Context, activeProbePlan) runtimetelemetry.ActiveProbeResult {
	executor.calls++
	return runtimetelemetry.CloneActiveProbe(executor.result)
}

func TestObserveVerifiedRuntimeTelemetryFailsClosedWithoutCachingOrRetry(t *testing.T) {
	bundle := runtimeTelemetryBundle(t, []netip.Prefix{netip.MustParsePrefix("10.42.0.9/24")}, runtimeTelemetryConfig("10.42.0.1", "10.42.0.2"))
	observer := &validatingRuntimeObserver{snapshot: validRuntimeObserverSnapshot()}
	if first := observeVerifiedRuntimeTelemetry(context.Background(), bundle, observer); first.State != RuntimeTelemetryObserved || first.Snapshot == nil {
		t.Fatalf("first observation = %#v", first)
	}
	observer.err = errors.New("observer unavailable")
	second := observeVerifiedRuntimeTelemetry(context.Background(), bundle, observer)
	if second != unknownRuntimeTelemetryObservation() || second.Snapshot != nil {
		t.Fatalf("failed observation reused stale data: %#v", second)
	}
	if observer.calls != 2 {
		t.Fatalf("observer calls = %d, want one per invocation", observer.calls)
	}

	if got := observeVerifiedRuntimeTelemetry(nil, bundle, observer); got != unknownRuntimeTelemetryObservation() {
		t.Fatalf("nil-context observation = %#v", got)
	}
	if got := observeVerifiedRuntimeTelemetry(context.Background(), bundle, nil); got != unknownRuntimeTelemetryObservation() {
		t.Fatalf("nil-observer observation = %#v", got)
	}
	if observer.calls != 2 {
		t.Fatalf("invalid preflight reached observer: calls=%d", observer.calls)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if got := observeVerifiedRuntimeTelemetry(canceled, bundle, observer); got != unknownRuntimeTelemetryObservation() {
		t.Fatalf("canceled-context observation = %#v", got)
	}
	if observer.calls != 2 {
		t.Fatalf("canceled context reached observer: calls=%d", observer.calls)
	}
}

func TestObserveVerifiedRuntimeTelemetryRevalidatesAlternateObserverResult(t *testing.T) {
	bundle := runtimeTelemetryBundle(t, []netip.Prefix{netip.MustParsePrefix("10.42.0.9/24")}, runtimeTelemetryConfig("10.42.0.1", "10.42.0.2"))
	invalid := validRuntimeObserverSnapshot()
	invalid.Lighthouses.Configured = 1
	observer := &rawRuntimeObserver{snapshot: invalid}
	got := observeVerifiedRuntimeTelemetry(context.Background(), bundle, observer)
	if got != unknownRuntimeTelemetryObservation() || observer.calls != 1 {
		t.Fatalf("invalid alternate snapshot was trusted: result=%#v calls=%d", got, observer.calls)
	}
}

func TestObserveVerifiedRuntimeTelemetryRejectsUntrustedTopologyBeforeTransport(t *testing.T) {
	tests := map[string]string{
		"missing lighthouse mapping":        "pki:\n  ca: /etc/nebula/ca.crt\n",
		"duplicate lighthouse mapping":      runtimeTelemetryConfig("10.42.0.1") + "lighthouse:\n  hosts: []\n",
		"missing hosts":                     "lighthouse:\n  am_lighthouse: false\nlisten:\n  port: 4242\n",
		"flow sequence":                     "lighthouse:\n  hosts: [\"10.42.0.1\"]\nlisten:\n  port: 4242\n",
		"unquoted scalar":                   "lighthouse:\n  hosts:\n    - 10.42.0.1\nlisten:\n  port: 4242\n",
		"YAML alias":                        "lighthouse:\n  hosts:\n    - *peer\nlisten:\n  port: 4242\n",
		"noncanonical IPv4":                 "lighthouse:\n  hosts:\n    - \"010.42.0.1\"\nlisten:\n  port: 4242\n",
		"IPv6":                              runtimeTelemetryConfig("fd00::1"),
		"outside verified prefix":           runtimeTelemetryConfig("10.43.0.1"),
		"duplicate address":                 runtimeTelemetryConfig("10.42.0.1", "10.42.0.1"),
		"empty block sequence":              "lighthouse:\n  hosts:\nlisten:\n  port: 4242\n",
		"empty flow with child":             "lighthouse:\n  hosts: []\n    - \"10.42.0.1\"\nlisten:\n  port: 4242\n",
		"empty flow with misindented child": "lighthouse:\n  hosts: []\n   - \"10.42.0.1\"\nlisten:\n  port: 4242\n",
		"CRLF":                              strings.ReplaceAll(runtimeTelemetryConfig("10.42.0.1"), "\n", "\r\n"),
		"oversized config":                  runtimeTelemetryConfig("10.42.0.1") + strings.Repeat("#", maxBundleFileSize),
	}
	tooMany := make([]string, runtimeobserver.MaxConfiguredLighthouses+1)
	for index := range tooMany {
		tooMany[index] = fmt.Sprintf("10.42.0.%d", index+1)
	}
	tests["too many addresses"] = runtimeTelemetryConfig(tooMany...)

	for name, config := range tests {
		t.Run(name, func(t *testing.T) {
			bundle := runtimeTelemetryBundle(t, []netip.Prefix{netip.MustParsePrefix("10.42.0.9/24")}, config)
			observer := &validatingRuntimeObserver{snapshot: validRuntimeObserverSnapshot()}
			got := observeVerifiedRuntimeTelemetry(context.Background(), bundle, observer)
			if got != unknownRuntimeTelemetryObservation() || observer.calls != 0 {
				t.Fatalf("untrusted topology reached observer: result=%#v calls=%d", got, observer.calls)
			}
		})
	}
}

func TestRuntimeValidationContextRejectsCertificateAmbiguity(t *testing.T) {
	validConfig := runtimeTelemetryConfig("10.42.0.1")
	validNetwork := netip.MustParsePrefix("10.42.0.9/24")
	tests := map[string]Bundle{
		"invalid PEM":            {Certificate: "not a certificate", CertificateFingerprint: strings.Repeat("a", 64), SignedConfig: validConfig},
		"multiple networks":      runtimeTelemetryBundle(t, []netip.Prefix{validNetwork, netip.MustParsePrefix("10.43.0.9/24")}, validConfig),
		"IPv6 network":           runtimeTelemetryBundle(t, []netip.Prefix{netip.MustParsePrefix("fd00::9/64")}, validConfig),
		"overbroad IPv4 network": runtimeTelemetryBundle(t, []netip.Prefix{netip.MustParsePrefix("10.42.0.9/8")}, validConfig),
	}
	mismatch := runtimeTelemetryBundle(t, []netip.Prefix{validNetwork}, validConfig)
	mismatch.CertificateFingerprint = strings.Repeat("f", 64)
	tests["fingerprint mismatch"] = mismatch
	tests["CA certificate"] = runtimeTelemetryCABundle(t, validConfig)
	trailing := runtimeTelemetryBundle(t, []netip.Prefix{validNetwork}, validConfig)
	trailing.Certificate += "unexpected trailing material"
	tests["trailing PEM material"] = trailing

	for name, bundle := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := runtimeValidationContextFromVerifiedBundle(bundle); !errors.Is(err, runtimeobserver.ErrProtocol) {
				t.Fatalf("error = %v, want protocol failure", err)
			}
		})
	}
}

type validatingRuntimeObserver struct {
	calls    int
	snapshot runtimeobserver.Snapshot
	err      error
}

type rawRuntimeObserver struct {
	calls    int
	snapshot runtimeobserver.Snapshot
}

func (o *rawRuntimeObserver) Observe(context.Context, runtimeobserver.ValidationContext) (runtimeobserver.Snapshot, error) {
	o.calls++
	return o.snapshot, nil
}

type realCertificateMetadataRunner struct{}

func (realCertificateMetadataRunner) Output(_ context.Context, name string, arguments ...string) ([]byte, error) {
	if name == "nebula" && len(arguments) == 1 && arguments[0] == "-version" {
		return []byte("Version: 1.10.3"), nil
	}
	if name != "nebula-cert" || len(arguments) != 4 || arguments[0] != "print" {
		return nil, errors.New("unexpected metadata command")
	}
	raw, err := os.ReadFile(arguments[3])
	if err != nil {
		return nil, err
	}
	certificate, remainder, err := nebulacert.UnmarshalCertificateFromPEM(raw)
	if err != nil || len(bytes.TrimSpace(remainder)) != 0 {
		return nil, errors.New("invalid certificate fixture")
	}
	fingerprint, err := certificate.Fingerprint()
	if err != nil {
		return nil, err
	}
	return json.Marshal([]map[string]any{{
		"fingerprint": fingerprint,
		"details":     map[string]any{"notAfter": certificate.NotAfter().UTC()},
	}})
}

func (realCertificateMetadataRunner) RunQuiet(context.Context, string, ...string) error { return nil }

func (o *validatingRuntimeObserver) Observe(_ context.Context, validation runtimeobserver.ValidationContext) (runtimeobserver.Snapshot, error) {
	o.calls++
	if o.err != nil {
		return runtimeobserver.Snapshot{}, o.err
	}
	if _, err := runtimeobserver.EncodeSnapshotLine(o.snapshot, o.snapshot.Nonce, validation); err != nil {
		return runtimeobserver.Snapshot{}, err
	}
	return o.snapshot, nil
}

func validRuntimeObserverSnapshot() runtimeobserver.Snapshot {
	handshakeAge, oldestRX := uint64(100), uint64(180_000)
	lighthouseHandshakeA, lighthouseHandshakeB := uint64(50), uint64(60)
	lighthouseRXA, lighthouseRXB := uint64(100), uint64(180_000)
	lighthouseMostRecentRX := uint64(100)
	return runtimeobserver.Snapshot{
		Schema: runtimeobserver.SnapshotSchema, Nonce: strings.Repeat("a", runtimeobserver.NonceHexLength),
		ProcessInstanceID: strings.Repeat("b", runtimeobserver.NonceHexLength), SampleSequence: 7, ProcessUptimeMS: 300_000,
		Handshakes: runtimeobserver.HandshakeSnapshot{CompletedTotal: 3, TimedOutTotal: 1, Pending: 1, MostRecentCompletionAgeMS: &handshakeAge},
		Peers:      runtimeobserver.PeerSnapshot{Established: 2, AuthenticatedRXWithin2m: 1, AuthenticatedRXWithin5m: 2, OldestAuthenticatedRXAgeMS: &oldestRX},
		Lighthouses: runtimeobserver.LighthouseSnapshot{
			Configured: 2, Established: 2, AuthenticatedRXWithin2m: 1, AuthenticatedRXWithin5m: 2,
			MostRecentAuthenticatedRXAgeMS: &lighthouseMostRecentRX, Entries: []runtimeobserver.LighthouseEntry{
				{VPNIP: "10.42.0.1", Established: true, LastHandshakeAgeMS: &lighthouseHandshakeA, LastAuthenticatedRXAgeMS: &lighthouseRXA},
				{VPNIP: "10.42.0.2", Established: true, LastHandshakeAgeMS: &lighthouseHandshakeB, LastAuthenticatedRXAgeMS: &lighthouseRXB},
			},
		},
	}
}

func runtimeTelemetryConfig(addresses ...string) string {
	var builder strings.Builder
	builder.WriteString("pki:\n  ca: /etc/nebula/ca.crt\n  cert: /etc/nebula/host.crt\n  key: /etc/nebula/host.key\n")
	builder.WriteString("static_host_map: {}\nlighthouse:\n  am_lighthouse: false\n  interval: 60\n")
	if len(addresses) == 0 {
		builder.WriteString("  hosts: []\n")
	} else {
		builder.WriteString("  hosts:\n")
		for _, address := range addresses {
			fmt.Fprintf(&builder, "    - %q\n", address)
		}
	}
	builder.WriteString("listen:\n  host: 0.0.0.0\n  port: 4242\n")
	return builder.String()
}

func runtimeTelemetryBundle(t *testing.T, networks []netip.Prefix, config string) Bundle {
	t.Helper()
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	caNetworks := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("fd00::/8")}
	ca, _, caPrivate, _ := nebulacerttest.NewTestCaCert(nebulacert.Version2, nebulacert.Curve_CURVE25519, now.Add(-time.Hour), now.Add(24*time.Hour), caNetworks, nil, nil)
	certificate, _, _, certificatePEM := nebulacerttest.NewTestCert(nebulacert.Version2, nebulacert.Curve_CURVE25519, ca, caPrivate, "runtime-node", now.Add(-time.Minute), now.Add(time.Hour), networks, nil, nil)
	fingerprint, err := certificate.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	return Bundle{Certificate: string(certificatePEM), CertificateFingerprint: fingerprint, SignedConfig: config}
}

func runtimeTelemetryCABundle(t *testing.T, config string) Bundle {
	t.Helper()
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	ca, _, _, caPEM := nebulacerttest.NewTestCaCert(nebulacert.Version2, nebulacert.Curve_CURVE25519, now.Add(-time.Hour), now.Add(time.Hour), []netip.Prefix{netip.MustParsePrefix("10.42.0.0/24")}, nil, nil)
	fingerprint, err := ca.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	return Bundle{Certificate: string(caPEM), CertificateFingerprint: fingerprint, SignedConfig: config}
}
