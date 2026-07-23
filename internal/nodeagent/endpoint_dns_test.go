//go:build !windows && !darwin

package nodeagent

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"mesh/internal/runtimetelemetry"
)

type recordingEndpointDNSResolver struct {
	mu        sync.Mutex
	responses map[string][]string
	calls     []string
}

func (resolver *recordingEndpointDNSResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	resolver.mu.Lock()
	resolver.calls = append(resolver.calls, host)
	response, found := resolver.responses[host]
	resolver.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !found {
		return nil, errors.New("not resolved")
	}
	return append([]string(nil), response...), nil
}

func TestAgentEndpointDNSReportsOnlyBoundedAggregateCounts(t *testing.T) {
	bundle := eligibleActiveProbeBundle(t, "10.42.0.1", "10.42.0.2")
	bundle.SignedConfig = strings.Replace(bundle.SignedConfig, "192.0.2.1:4242", "LH.Example.:4242", 1)
	bundle.SignedConfig = strings.Replace(bundle.SignedConfig, "192.0.2.2:4242", "missing.example:4242", 1)
	resolver := &recordingEndpointDNSResolver{responses: map[string][]string{
		"LH.Example.": {"198.51.100.8", "not-an-address"},
	}}
	agent := &Agent{Store: newActiveProbeOrchestrationStore(t), endpointDNSResolver: resolver}
	result := agent.resolveEndpointDNS(context.Background(), bundle)
	if result.State != runtimetelemetry.EndpointDNSObserved || result.SampleAgeMS == nil || *result.SampleAgeMS != 0 ||
		result.DNSNames != 2 || result.ResolvedNames != 1 {
		t.Fatalf("endpoint DNS result = %#v", result)
	}
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"LH.Example", "missing.example", "198.51.100.8", "error"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("endpoint DNS result exposed private resolver detail: %s", raw)
		}
	}
}

func TestAgentEndpointDNSHandlesIPOnlyDeduplicationAndInvalidEvidence(t *testing.T) {
	store := newActiveProbeOrchestrationStore(t)
	resolver := &recordingEndpointDNSResolver{responses: map[string][]string{
		"same.example":  {"203.0.113.9"},
		"SAME.EXAMPLE.": {"203.0.113.9"},
	}}
	agent := &Agent{Store: store, endpointDNSResolver: resolver}
	if result := agent.resolveEndpointDNS(context.Background(), eligibleActiveProbeBundle(t, "10.42.0.1")); result.State != runtimetelemetry.EndpointDNSObserved || result.SampleAgeMS == nil || result.DNSNames != 0 || result.ResolvedNames != 0 {
		t.Fatalf("IP-only result = %#v", result)
	}

	bundle := eligibleActiveProbeBundle(t, "10.42.0.1", "10.42.0.2")
	bundle.SignedConfig = strings.Replace(bundle.SignedConfig, "192.0.2.1:4242", "same.example:4242", 1)
	bundle.SignedConfig = strings.Replace(bundle.SignedConfig, "192.0.2.2:4242", "SAME.EXAMPLE.:4243", 1)
	result := agent.resolveEndpointDNS(context.Background(), bundle)
	if result.State != runtimetelemetry.EndpointDNSObserved || result.DNSNames != 1 || result.ResolvedNames != 1 {
		t.Fatalf("deduplicated result = %#v", result)
	}

	broken := bundle
	broken.SignedConfig = strings.Replace(broken.SignedConfig, "same.example:4242", "bad_name.example:4242", 1)
	if result := agent.resolveEndpointDNS(context.Background(), broken); result != runtimetelemetry.UnavailableEndpointDNS() {
		t.Fatalf("invalid endpoint result = %#v", result)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if result := agent.resolveEndpointDNS(cancelled, bundle); result != runtimetelemetry.UnavailableEndpointDNS() {
		t.Fatalf("cancelled result = %#v", result)
	}
}
