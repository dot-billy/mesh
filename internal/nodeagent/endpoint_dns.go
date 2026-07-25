package nodeagent

import (
	"context"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"mesh/internal/runtimetelemetry"
)

const (
	endpointDNSLookupTimeout = 3 * time.Second
	endpointDNSWorkers       = 4
)

type endpointDNSResolver interface {
	LookupHost(context.Context, string) ([]string, error)
}

func (a *Agent) resolveEndpointDNS(ctx context.Context, bundle Bundle) runtimetelemetry.EndpointDNSResult {
	if ctx == nil || ctx.Err() != nil || a == nil || a.Store == nil {
		return runtimetelemetry.UnavailableEndpointDNS()
	}
	topology, err := verifiedRuntimeTopologyFromBundle(bundle)
	if err != nil {
		return runtimetelemetry.UnavailableEndpointDNS()
	}
	endpoints, err := parseSignedStaticHostEndpoints(bundle.SignedConfig, topology.network)
	if err != nil {
		return runtimetelemetry.UnavailableEndpointDNS()
	}
	names := make(map[string]string)
	for _, endpoint := range endpoints {
		host, port, splitErr := net.SplitHostPort(endpoint)
		if splitErr != nil || host == "" || !validRenderedEndpointPort(port) {
			return runtimetelemetry.UnavailableEndpointDNS()
		}
		if net.ParseIP(host) != nil {
			continue
		}
		key, ok := canonicalRenderedDNSName(host)
		if !ok {
			return runtimetelemetry.UnavailableEndpointDNS()
		}
		names[key] = host
	}
	if len(names) > int(runtimetelemetry.MaxEndpointDNSNames) {
		return runtimetelemetry.UnavailableEndpointDNS()
	}
	if len(names) == 0 {
		return runtimetelemetry.ObservedEndpointDNS(0, 0)
	}
	resolver := a.endpointDNSResolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	resolved, complete := resolveEndpointDNSNames(ctx, names, resolver)
	if !complete {
		return runtimetelemetry.UnavailableEndpointDNS()
	}
	result := runtimetelemetry.ObservedEndpointDNS(uint64(len(names)), resolved)
	if runtimetelemetry.ValidateEndpointDNS(result) != nil {
		return runtimetelemetry.UnavailableEndpointDNS()
	}
	return result
}

func resolveEndpointDNSNames(ctx context.Context, names map[string]string, resolver endpointDNSResolver) (uint64, bool) {
	if ctx == nil || ctx.Err() != nil || resolver == nil || len(names) == 0 || len(names) > int(runtimetelemetry.MaxEndpointDNSNames) {
		return 0, false
	}
	lookupCtx, cancel := context.WithTimeout(ctx, endpointDNSLookupTimeout)
	defer cancel()
	ordered := make([]string, 0, len(names))
	for key := range names {
		ordered = append(ordered, key)
	}
	sort.Strings(ordered)
	jobs := make(chan string)
	results := make(chan bool)
	workers := min(endpointDNSWorkers, len(ordered))
	var wait sync.WaitGroup
	wait.Add(workers)
	for worker := 0; worker < workers; worker++ {
		go func() {
			defer wait.Done()
			for key := range jobs {
				addresses, lookupErr := resolver.LookupHost(lookupCtx, names[key])
				resolved := false
				if lookupErr == nil {
					for _, value := range addresses {
						if address, parseErr := netip.ParseAddr(value); parseErr == nil && address.IsValid() {
							resolved = true
							break
						}
					}
				}
				select {
				case results <- resolved:
				case <-lookupCtx.Done():
					return
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, key := range ordered {
			select {
			case jobs <- key:
			case <-lookupCtx.Done():
				return
			}
		}
	}()
	go func() {
		wait.Wait()
		close(results)
	}()
	resolved := uint64(0)
	completed := 0
	for completed < len(ordered) {
		select {
		case value, open := <-results:
			if !open {
				completed = len(ordered)
				continue
			}
			completed++
			if value {
				resolved++
			}
		case <-lookupCtx.Done():
			if ctx.Err() != nil {
				return 0, false
			}
			completed = len(ordered)
		}
	}
	if ctx.Err() != nil {
		return 0, false
	}
	return resolved, true
}

func validRenderedEndpointPort(value string) bool {
	parsed, err := strconv.Atoi(value)
	return err == nil && parsed >= 1 && parsed <= 65535 && strconv.Itoa(parsed) == value
}

func canonicalRenderedDNSName(value string) (string, bool) {
	if value == "" || len(value) > 253 {
		return "", false
	}
	trimmed := strings.TrimSuffix(value, ".")
	if trimmed == "" || strings.Contains(trimmed, "..") {
		return "", false
	}
	for _, label := range strings.Split(trimmed, ".") {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", false
		}
		for _, character := range label {
			if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
				(character >= '0' && character <= '9') || character == '-' {
				continue
			}
			return "", false
		}
	}
	return strings.ToLower(trimmed), true
}

var _ endpointDNSResolver = (*net.Resolver)(nil)
