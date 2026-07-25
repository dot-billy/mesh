package nodeagent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	nebulacert "github.com/slackhq/nebula/cert"

	"mesh/internal/runtimeobserver"
	"mesh/internal/runtimetelemetry"
)

const (
	RuntimeTelemetryObservationVersionV1 = runtimetelemetry.VersionV1
	RuntimeTelemetryObservationVersionV2 = runtimetelemetry.VersionV2
)

const (
	RuntimeTelemetryUnknown  = runtimetelemetry.StateUnknown
	RuntimeTelemetryObserved = runtimetelemetry.StateObserved
)

const activeProbeCadence = 30 * time.Second

// RuntimeTelemetryObserver is the narrow transport seam used by the agent-side
// adapter. The production implementation is runtimeobserver.Client.
type RuntimeTelemetryObserver interface {
	Observe(context.Context, runtimeobserver.ValidationContext) (runtimeobserver.Snapshot, error)
}

// These aliases keep the agent adapter vocabulary stable while making its
// output the exact separately versioned persistence/API allowlist. The
// lifecycle heartbeat schema remains unchanged.
type RuntimeTelemetryObservation = runtimetelemetry.Observation
type RuntimeTelemetrySnapshot = runtimetelemetry.Snapshot
type RuntimeHandshakeTelemetry = runtimetelemetry.HandshakeAggregate
type RuntimePeerTelemetry = runtimetelemetry.PeerAggregate
type RuntimeLighthouseTelemetry = runtimetelemetry.LighthouseAggregate

// ObserveRuntimeTelemetry loads and revalidates the active signed bundle, then
// performs exactly one bounded observer request. Every failure is represented
// as a fresh unknown result; this method has no cache and does not alter the
// lifecycle heartbeat or configuration freshness planes.
func (a *Agent) ObserveRuntimeTelemetry(ctx context.Context) RuntimeTelemetryObservation {
	a.mu.Lock()
	defer a.mu.Unlock()
	if ctx == nil || ctx.Err() != nil || a.ready() != nil {
		return unknownRuntimeTelemetryObservation()
	}
	_, current, err := a.loadReconciledState(ctx)
	if err != nil {
		return unknownRuntimeTelemetryObservation()
	}
	observer := a.RuntimeObserver
	if observer == nil {
		observer = runtimeobserver.Client{}
	}
	return observeVerifiedRuntimeTelemetry(ctx, current, observer)
}

// ReportRuntimeTelemetry revalidates the active bundle, takes exactly one
// bounded local observation, and posts it against the exact lifecycle
// heartbeat sequence already persisted by Heartbeat. Observer failures are
// reported as a fresh unknown observation; bundle, state, or transport failures
// are returned without changing agent lifecycle state.
func (a *Agent) ReportRuntimeTelemetry(ctx context.Context, heartbeatSequence int64) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if ctx == nil {
		return errors.New("runtime telemetry context is nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := a.ready(); err != nil {
		return err
	}
	if heartbeatSequence < 1 {
		return fmt.Errorf("%w: runtime telemetry heartbeat sequence is invalid", runtimetelemetry.ErrInvalid)
	}
	state, current, err := a.loadReconciledState(ctx)
	if err != nil {
		return err
	}
	if state.HeartbeatSequence != heartbeatSequence {
		return fmt.Errorf("%w: runtime telemetry does not match the current local heartbeat", runtimetelemetry.ErrConflict)
	}
	observer := a.RuntimeObserver
	if observer == nil {
		observer = runtimeobserver.Client{}
	}
	observation := observeVerifiedRuntimeTelemetry(ctx, current, observer)
	activeProbe := a.resolveActiveProbe(ctx, current)
	routeOverlap := a.resolveRouteOverlap(ctx, current)
	endpointDNS := a.resolveEndpointDNS(ctx, current)
	client, err := NewClient(state.ServerURL, state.Bearer, a.HTTPClient)
	if err != nil {
		return err
	}
	return client.ReportRuntimeTelemetry(ctx, runtimetelemetry.ReportInput{
		HeartbeatSequence: heartbeatSequence,
		Observation:       observation,
		ActiveProbe:       &activeProbe,
		RouteOverlap:      &routeOverlap,
		EndpointDNS:       &endpointDNS,
	})
}

func (a *Agent) resolveActiveProbe(ctx context.Context, bundle Bundle) runtimetelemetry.ActiveProbeResult {
	if ctx == nil || ctx.Err() != nil || a == nil || a.Store == nil {
		return runtimetelemetry.UnavailableActiveProbe()
	}
	plan, err := activeProbePlanFromVerifiedBundle(bundle)
	if err != nil {
		return runtimetelemetry.UnavailableActiveProbe()
	}
	if len(plan.targets) == 0 {
		return runtimetelemetry.NotEligibleActiveProbe()
	}
	executor := a.activeProbeExecutor
	if executor == nil {
		executor = newPlatformActiveProbeExecutor()
	}
	if executor == nil {
		return runtimetelemetry.UnavailableActiveProbe()
	}
	if !executor.Supported() {
		return runtimetelemetry.UnsupportedActiveProbe()
	}
	now := a.currentTime()
	if now.IsZero() || now.Location() != time.UTC {
		return runtimetelemetry.UnavailableActiveProbe()
	}
	planSHA256 := activeProbePlanSHA256(plan)
	journal, err := a.loadRuntimeActiveProbeJournal()
	switch {
	case err == nil:
		if journal.ReservedAt.After(now) {
			return runtimetelemetry.UnavailableActiveProbe()
		}
		elapsed := now.Sub(journal.ReservedAt)
		if elapsed < activeProbeCadence {
			if journal.PlanSHA256 != planSHA256 {
				return runtimetelemetry.UnavailableActiveProbe()
			}
			return cachedActiveProbeResult(journal.Result, elapsed)
		}
	case errors.Is(err, os.ErrNotExist):
		// Missing journal state is the only create-new path.
	default:
		return runtimetelemetry.UnavailableActiveProbe()
	}

	reservation := activeProbeJournal{
		Schema: activeProbeJournalSchemaV1, PlanSHA256: planSHA256,
		ReservedAt: now, Result: runtimetelemetry.UnavailableActiveProbe(),
	}
	if err := a.saveRuntimeActiveProbeJournal(reservation); err != nil {
		return runtimetelemetry.UnavailableActiveProbe()
	}
	result := executor.Probe(ctx, plan)
	if ctx.Err() != nil || runtimetelemetry.ValidateActiveProbe(result) != nil {
		return runtimetelemetry.UnavailableActiveProbe()
	}
	completed := reservation
	completed.Result = runtimetelemetry.CloneActiveProbe(result)
	if err := a.saveRuntimeActiveProbeJournal(completed); err != nil {
		return runtimetelemetry.UnavailableActiveProbe()
	}
	return runtimetelemetry.CloneActiveProbe(result)
}

func (a *Agent) loadRuntimeActiveProbeJournal() (activeProbeJournal, error) {
	if a.loadActiveProbeJournal != nil {
		return a.loadActiveProbeJournal()
	}
	return a.Store.LoadActiveProbeJournal()
}

func (a *Agent) saveRuntimeActiveProbeJournal(journal activeProbeJournal) error {
	if a.saveActiveProbeJournal != nil {
		return a.saveActiveProbeJournal(cloneActiveProbeJournal(journal))
	}
	return a.Store.SaveActiveProbeJournal(journal)
}

func cachedActiveProbeResult(result runtimetelemetry.ActiveProbeResult, elapsed time.Duration) runtimetelemetry.ActiveProbeResult {
	if elapsed < 0 || (result.State != runtimetelemetry.ProbeAttempted && result.State != runtimetelemetry.ProbeCapabilityUnavailable) || result.SampleAgeMS == nil {
		return runtimetelemetry.UnavailableActiveProbe()
	}
	ageIncrement := uint64(elapsed / time.Millisecond)
	if ageIncrement > runtimetelemetry.MaxActiveProbeSampleAgeMS || *result.SampleAgeMS > runtimetelemetry.MaxActiveProbeSampleAgeMS-ageIncrement {
		return runtimetelemetry.UnavailableActiveProbe()
	}
	result = runtimetelemetry.CloneActiveProbe(result)
	*result.SampleAgeMS += ageIncrement
	if err := runtimetelemetry.ValidateActiveProbe(result); err != nil {
		return runtimetelemetry.UnavailableActiveProbe()
	}
	return result
}

func activeProbePlanSHA256(plan activeProbePlan) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte("mesh-active-probe-plan-v1\x00"))
	if plan.localAddress.Is4() {
		address := plan.localAddress.As4()
		_, _ = hash.Write(address[:])
	}
	_, _ = hash.Write([]byte{byte(len(plan.targets))})
	for _, target := range plan.targets {
		if target.Is4() {
			address := target.As4()
			_, _ = hash.Write(address[:])
		}
	}
	return fmt.Sprintf("%x", hash.Sum(nil))
}

// observeVerifiedRuntimeTelemetry is deliberately package-private: its Bundle
// argument must be the result of loadReconciledState, which has revalidated the
// immutable signed config and live host certificate.
func observeVerifiedRuntimeTelemetry(ctx context.Context, bundle Bundle, observer RuntimeTelemetryObserver) RuntimeTelemetryObservation {
	if ctx == nil || ctx.Err() != nil || observer == nil {
		return unknownRuntimeTelemetryObservation()
	}
	validation, err := runtimeValidationContextFromVerifiedBundle(bundle)
	if err != nil || ctx.Err() != nil {
		return unknownRuntimeTelemetryObservation()
	}
	snapshot, err := observer.Observe(ctx, validation)
	if err != nil || ctx.Err() != nil {
		return unknownRuntimeTelemetryObservation()
	}
	// Revalidate at the adapter boundary so an injected or future alternate
	// transport cannot bypass the same protocol/topology invariants enforced by
	// the production client.
	if _, err := runtimeobserver.EncodeSnapshotLine(snapshot, snapshot.Nonce, validation); err != nil {
		return unknownRuntimeTelemetryObservation()
	}
	observationVersion := RuntimeTelemetryObservationVersionV2
	if snapshot.Schema == runtimeobserver.SnapshotSchemaV1 {
		observationVersion = RuntimeTelemetryObservationVersionV1
	}
	return RuntimeTelemetryObservation{
		Version: observationVersion,
		State:   RuntimeTelemetryObserved,
		Snapshot: &RuntimeTelemetrySnapshot{
			ProcessInstanceID: snapshot.ProcessInstanceID,
			SampleSequence:    snapshot.SampleSequence, ProcessUptimeMS: snapshot.ProcessUptimeMS,
			Handshakes: RuntimeHandshakeTelemetry{
				CompletedTotal: snapshot.Handshakes.CompletedTotal, TimedOutTotal: snapshot.Handshakes.TimedOutTotal,
				Pending: snapshot.Handshakes.Pending, MostRecentCompletionAgeMS: cloneRuntimeTelemetryAge(snapshot.Handshakes.MostRecentCompletionAgeMS),
			},
			Peers: RuntimePeerTelemetry{
				Established:             snapshot.Peers.Established,
				AuthenticatedRXWithin2m: snapshot.Peers.AuthenticatedRXWithin2m,
				AuthenticatedRXWithin5m: snapshot.Peers.AuthenticatedRXWithin5m, OldestAuthenticatedRXAgeMS: cloneRuntimeTelemetryAge(snapshot.Peers.OldestAuthenticatedRXAgeMS),
			},
			Lighthouses: RuntimeLighthouseTelemetry{
				Configured:                     snapshot.Lighthouses.Configured,
				Established:                    snapshot.Lighthouses.Established,
				AuthenticatedRXWithin2m:        snapshot.Lighthouses.AuthenticatedRXWithin2m,
				AuthenticatedRXWithin5m:        snapshot.Lighthouses.AuthenticatedRXWithin5m,
				MostRecentAuthenticatedRXAgeMS: cloneRuntimeTelemetryAge(snapshot.Lighthouses.MostRecentAuthenticatedRXAgeMS),
				Overflow:                       snapshot.Lighthouses.Overflow,
			},
		},
	}
}

func cloneRuntimeTelemetryAge(value *uint64) *uint64 {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func unknownRuntimeTelemetryObservation() RuntimeTelemetryObservation {
	return RuntimeTelemetryObservation{Version: RuntimeTelemetryObservationVersionV2, State: RuntimeTelemetryUnknown}
}

func runtimeValidationContextFromVerifiedBundle(bundle Bundle) (runtimeobserver.ValidationContext, error) {
	topology, err := verifiedRuntimeTopologyFromBundle(bundle)
	if err != nil {
		return runtimeobserver.ValidationContext{}, err
	}
	return runtimeobserver.NewValidationContext(topology.network, topology.lighthouses)
}

type verifiedRuntimeTopology struct {
	localAddress netip.Addr
	network      netip.Prefix
	lighthouses  []netip.Addr
}

func verifiedRuntimeTopologyFromBundle(bundle Bundle) (verifiedRuntimeTopology, error) {
	certificate, remainder, err := nebulacert.UnmarshalCertificateFromPEM([]byte(bundle.Certificate))
	if err != nil || len(bytes.TrimSpace(remainder)) != 0 || certificate.IsCA() {
		return verifiedRuntimeTopology{}, runtimeobserver.ErrProtocol
	}
	fingerprint, err := certificate.Fingerprint()
	if err != nil || fingerprint != bundle.CertificateFingerprint {
		return verifiedRuntimeTopology{}, runtimeobserver.ErrProtocol
	}
	networks := certificate.Networks()
	if len(networks) != 1 || !networks[0].IsValid() || !networks[0].Addr().Is4() {
		return verifiedRuntimeTopology{}, runtimeobserver.ErrProtocol
	}
	bits := networks[0].Bits()
	if bits < 16 || bits > 28 {
		return verifiedRuntimeTopology{}, runtimeobserver.ErrProtocol
	}
	lighthouses, err := parseSignedLighthouseHosts(bundle.SignedConfig)
	if err != nil {
		return verifiedRuntimeTopology{}, err
	}
	network := networks[0].Masked()
	if _, err := runtimeobserver.NewValidationContext(network, lighthouses); err != nil {
		return verifiedRuntimeTopology{}, err
	}
	return verifiedRuntimeTopology{localAddress: networks[0].Addr(), network: network, lighthouses: append([]netip.Addr(nil), lighthouses...)}, nil
}

// parseSignedLighthouseHosts strictly extracts the hosts value from an already
// signature-verified Mesh renderer output. It requires a unique top-level
// lighthouse mapping and accepts hosts only as [] or a block sequence of
// canonical, explicitly quoted IPv4 strings. It does not validate unrelated
// lighthouse keys/order or apply YAML coercions, aliases, merges, or defaults.
func parseSignedLighthouseHosts(config string) ([]netip.Addr, error) {
	if config == "" || len(config) > maxBundleFileSize || !utf8.ValidString(config) || strings.ContainsRune(config, '\r') {
		return nil, runtimeobserver.ErrProtocol
	}
	lines := strings.Split(config, "\n")
	lighthouseLine := -1
	for index, line := range lines {
		if line == "lighthouse:" {
			if lighthouseLine != -1 {
				return nil, runtimeobserver.ErrProtocol
			}
			lighthouseLine = index
		}
	}
	if lighthouseLine == -1 {
		return nil, runtimeobserver.ErrProtocol
	}

	hostsLine := -1
	empty := false
	sectionEnd := len(lines)
	for index := lighthouseLine + 1; index < len(lines); index++ {
		line := lines[index]
		if line != "" && line[0] != ' ' {
			sectionEnd = index
			break
		}
		if line == "  hosts: []" || line == "  hosts:" {
			if hostsLine != -1 {
				return nil, runtimeobserver.ErrProtocol
			}
			hostsLine = index
			empty = line == "  hosts: []"
			continue
		}
		if strings.HasPrefix(strings.TrimSpace(line), "hosts:") {
			return nil, runtimeobserver.ErrProtocol
		}
	}
	if hostsLine == -1 {
		return nil, runtimeobserver.ErrProtocol
	}
	if empty {
		for index := hostsLine + 1; index < sectionEnd; index++ {
			line := lines[index]
			if line == "" {
				continue
			}
			if strings.HasPrefix(line, "  ") && len(line) > 2 && line[2] != ' ' {
				break
			}
			return nil, runtimeobserver.ErrProtocol
		}
		return []netip.Addr{}, nil
	}

	addresses := make([]netip.Addr, 0, 2)
	for index := hostsLine + 1; index < sectionEnd; index++ {
		line := lines[index]
		if strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "    ") {
			break
		}
		if !strings.HasPrefix(line, "    - ") || strings.HasPrefix(line, "     ") {
			return nil, runtimeobserver.ErrProtocol
		}
		raw := strings.TrimPrefix(line, "    - ")
		var value string
		if json.Unmarshal([]byte(raw), &value) != nil || strconv.Quote(value) != raw {
			return nil, runtimeobserver.ErrProtocol
		}
		address, err := netip.ParseAddr(value)
		if err != nil || !address.Is4() || address.String() != value {
			return nil, runtimeobserver.ErrProtocol
		}
		addresses = append(addresses, address)
		if len(addresses) > runtimeobserver.MaxConfiguredLighthouses {
			return nil, runtimeobserver.ErrProtocol
		}
	}
	if len(addresses) == 0 {
		return nil, runtimeobserver.ErrProtocol
	}
	return addresses, nil
}
