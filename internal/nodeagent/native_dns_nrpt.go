package nodeagent

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"sync"

	"mesh/internal/control"
)

const (
	windowsNativeDNSDisplayName = "Mesh Native DNS"
	windowsNativeDNSComment     = "Managed exclusively by Mesh node agent v1"
	windowsNativeDNSPort        = 53
)

var windowsNRPTRuleNamePattern = regexp.MustCompile(`^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$`)

type windowsNRPTRecord struct {
	Comment                  string   `json:"comment"`
	DirectAccessEnabled      bool     `json:"direct_access_enabled"`
	DisplayName              string   `json:"display_name"`
	DNSSecEnabled            bool     `json:"dnssec_enabled"`
	DNSSecValidationRequired bool     `json:"dnssec_validation_required"`
	Name                     string   `json:"name,omitempty"`
	NameEncoding             string   `json:"name_encoding"`
	NameServers              []string `json:"name_servers"`
	Namespaces               []string `json:"namespaces"`
}

type windowsNRPTSnapshot struct {
	Configured []windowsNRPTRecord `json:"configured"`
	Effective  []windowsNRPTRecord `json:"effective"`
}

type windowsNRPTBackend interface {
	Inspect(context.Context) (windowsNRPTSnapshot, error)
	Add(context.Context, string, string) error
	Remove(context.Context, string) error
}

type windowsNativeDNSActiveState struct {
	policy   control.NativeDNSPolicy
	ruleName string
	proxy    nativeDNSProxyHandle
}

type windowsNativeDNSManager struct {
	backend    windowsNRPTBackend
	startProxy func(control.NativeDNSPolicy, int) (nativeDNSProxyHandle, error)

	mu     sync.Mutex
	active *windowsNativeDNSActiveState
}

func (manager *windowsNativeDNSManager) Reconcile(ctx context.Context, signedConfig string) error {
	policy, enabled, err := parseNativeDNSConfig(signedConfig)
	if err != nil {
		return err
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if manager.backend == nil {
		return errors.New("Windows native DNS manager backend is unavailable")
	}
	if !enabled {
		return manager.disableLocked(ctx)
	}
	if manager.startProxy == nil {
		return errors.New("Windows native DNS adapter constructor is unavailable")
	}
	address, err := netip.ParseAddr(policy.LocalIP)
	if err != nil || !address.Is4() || address.IsLoopback() || address.IsUnspecified() {
		return errors.New("signed Windows native DNS local address is invalid")
	}
	if manager.active != nil && reflect.DeepEqual(manager.active.policy, policy) && manager.active.proxy != nil {
		if err := manager.proveActiveLocked(ctx, manager.active); err == nil {
			return nil
		}
	}
	var previous *control.NativeDNSPolicy
	if manager.active != nil {
		copy := manager.active.policy
		previous = &copy
	}
	if err := manager.disableLocked(ctx); err != nil {
		return err
	}
	if err := manager.establishLocked(ctx, policy); err != nil {
		if previous != nil {
			restoreErr := manager.establishLocked(ctx, *previous)
			if restoreErr != nil {
				return errors.Join(err, fmt.Errorf("restore previous Windows native DNS policy: %w", restoreErr))
			}
		}
		return err
	}
	return nil
}

func (manager *windowsNativeDNSManager) Disable(ctx context.Context) error {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if manager.backend == nil {
		return errors.New("Windows native DNS manager backend is unavailable")
	}
	return manager.disableLocked(ctx)
}

// disableLocked closes the local adapter before removing persistent NRPT
// state. If removal fails, the suffix remains fail-closed against a stopped
// local server and the active identity is retained for an exact retry.
func (manager *windowsNativeDNSManager) disableLocked(ctx context.Context) error {
	prior := manager.active
	var closeErr error
	if prior != nil && prior.proxy != nil {
		if err := prior.proxy.Close(); err != nil {
			closeErr = fmt.Errorf("close Windows native DNS adapter: %w", err)
		}
		prior.proxy = nil
	}
	snapshot, err := manager.backend.Inspect(ctx)
	if err != nil {
		return fmt.Errorf("inspect Windows NRPT before cleanup: %w", err)
	}
	owned, err := ownedWindowsNRPTRules(snapshot.Configured)
	if err != nil {
		return err
	}
	for _, rule := range owned {
		removeErr := manager.backend.Remove(ctx, rule.Name)
		if removeErr == nil {
			continue
		}
		observed, inspectErr := manager.backend.Inspect(ctx)
		if inspectErr != nil {
			return errors.Join(fmt.Errorf("remove Mesh-owned Windows NRPT rule %s: %w", rule.Name, removeErr), inspectErr)
		}
		remaining, ownershipErr := ownedWindowsNRPTRules(observed.Configured)
		if ownershipErr != nil {
			return errors.Join(removeErr, ownershipErr)
		}
		stillPresent := false
		for _, candidate := range remaining {
			if strings.EqualFold(candidate.Name, rule.Name) {
				stillPresent = true
			}
		}
		if stillPresent {
			return fmt.Errorf("remove Mesh-owned Windows NRPT rule %s: %w", rule.Name, removeErr)
		}
	}
	after, err := manager.backend.Inspect(ctx)
	if err != nil {
		return fmt.Errorf("prove Windows NRPT cleanup: %w", err)
	}
	remaining, err := ownedWindowsNRPTRules(after.Configured)
	if err != nil {
		return err
	}
	if len(remaining) != 0 {
		return errors.New("Mesh-owned Windows NRPT state remains after cleanup")
	}
	manager.active = nil
	return closeErr
}

func (manager *windowsNativeDNSManager) establishLocked(ctx context.Context, policy control.NativeDNSPolicy) error {
	namespace := "." + policy.SearchDomain
	snapshot, err := manager.backend.Inspect(ctx)
	if err != nil {
		return fmt.Errorf("inspect Windows NRPT before activation: %w", err)
	}
	if err := rejectWindowsNRPTNamespaceConflict(snapshot.Configured, namespace); err != nil {
		return err
	}
	owned, err := ownedWindowsNRPTRules(snapshot.Configured)
	if err != nil {
		return err
	}
	if len(owned) != 0 {
		return errors.New("stale Mesh-owned Windows NRPT state must be removed before activation")
	}
	proxy, err := manager.startProxy(policy, windowsNativeDNSPort)
	if err != nil {
		return fmt.Errorf("start Windows native DNS adapter on UDP 53: %w", err)
	}
	keepProxy := false
	defer func() {
		if !keepProxy {
			_ = proxy.Close()
		}
	}()
	addErr := manager.backend.Add(ctx, namespace, policy.LocalIP)
	after, inspectErr := manager.backend.Inspect(ctx)
	if inspectErr != nil {
		manager.cleanupOwnedBestEffort(ctx)
		return errors.Join(addErr, fmt.Errorf("inspect Windows NRPT after activation: %w", inspectErr))
	}
	ruleName, proveErr := proveWindowsNRPTSnapshot(after, namespace, policy.LocalIP, "")
	if proveErr != nil {
		manager.cleanupOwnedBestEffort(ctx)
		if addErr != nil {
			return errors.Join(fmt.Errorf("add Windows native DNS NRPT rule: %w", addErr), proveErr)
		}
		return proveErr
	}
	manager.active = &windowsNativeDNSActiveState{policy: policy, ruleName: ruleName, proxy: proxy}
	keepProxy = true
	return nil
}

func (manager *windowsNativeDNSManager) proveActiveLocked(ctx context.Context, active *windowsNativeDNSActiveState) error {
	if active == nil || active.proxy == nil || active.proxy.Port() != windowsNativeDNSPort {
		return errors.New("Windows native DNS adapter is not bound to UDP 53")
	}
	snapshot, err := manager.backend.Inspect(ctx)
	if err != nil {
		return err
	}
	_, err = proveWindowsNRPTSnapshot(snapshot, "."+active.policy.SearchDomain, active.policy.LocalIP, active.ruleName)
	return err
}

func (manager *windowsNativeDNSManager) cleanupOwnedBestEffort(ctx context.Context) {
	snapshot, err := manager.backend.Inspect(ctx)
	if err != nil {
		return
	}
	owned, err := ownedWindowsNRPTRules(snapshot.Configured)
	if err != nil {
		return
	}
	for _, rule := range owned {
		_ = manager.backend.Remove(ctx, rule.Name)
	}
}

func ownedWindowsNRPTRules(records []windowsNRPTRecord) ([]windowsNRPTRecord, error) {
	owned := make([]windowsNRPTRecord, 0)
	seen := make(map[string]struct{})
	for _, record := range records {
		if record.Comment != windowsNativeDNSComment || record.DisplayName != windowsNativeDNSDisplayName {
			continue
		}
		if !windowsNRPTRuleNamePattern.MatchString(record.Name) {
			return nil, errors.New("Mesh-owned Windows NRPT rule has a noncanonical identity")
		}
		key := strings.ToLower(record.Name)
		if _, duplicate := seen[key]; duplicate {
			return nil, errors.New("Windows NRPT inventory contains a duplicate Mesh-owned rule identity")
		}
		seen[key] = struct{}{}
		owned = append(owned, record)
	}
	sort.Slice(owned, func(left, right int) bool {
		return strings.ToLower(owned[left].Name) < strings.ToLower(owned[right].Name)
	})
	return owned, nil
}

func rejectWindowsNRPTNamespaceConflict(records []windowsNRPTRecord, namespace string) error {
	for _, record := range records {
		if len(record.Namespaces) != 1 || !strings.EqualFold(record.Namespaces[0], namespace) {
			continue
		}
		if record.Comment != windowsNativeDNSComment || record.DisplayName != windowsNativeDNSDisplayName {
			return fmt.Errorf("Windows NRPT namespace %q is already owned by another policy", namespace)
		}
	}
	return nil
}

func proveWindowsNRPTSnapshot(snapshot windowsNRPTSnapshot, namespace, nameServer, expectedName string) (string, error) {
	if err := rejectWindowsNRPTNamespaceConflict(snapshot.Configured, namespace); err != nil {
		return "", err
	}
	owned, err := ownedWindowsNRPTRules(snapshot.Configured)
	if err != nil {
		return "", err
	}
	if len(owned) != 1 {
		return "", fmt.Errorf("Windows NRPT contains %d Mesh-owned rules, want exactly one", len(owned))
	}
	rule := owned[0]
	if expectedName != "" && !strings.EqualFold(rule.Name, expectedName) {
		return "", errors.New("Windows NRPT rule identity changed")
	}
	if !exactWindowsNRPTRecord(rule, namespace, nameServer, true) {
		return "", errors.New("Mesh-owned Windows NRPT rule differs from signed policy")
	}
	matchingEffective := 0
	for _, record := range snapshot.Effective {
		if len(record.Namespaces) == 1 && strings.EqualFold(record.Namespaces[0], namespace) {
			if !exactWindowsNRPTRecord(record, namespace, nameServer, false) {
				return "", errors.New("effective Windows NRPT policy differs from the Mesh-owned rule")
			}
			matchingEffective++
		}
	}
	if matchingEffective != 1 {
		return "", fmt.Errorf("Windows NRPT contains %d exact effective policies, want one", matchingEffective)
	}
	return rule.Name, nil
}

func exactWindowsNRPTRecord(record windowsNRPTRecord, namespace, nameServer string, configured bool) bool {
	if len(record.Namespaces) != 1 || !strings.EqualFold(record.Namespaces[0], namespace) ||
		len(record.NameServers) != 1 || record.NameServers[0] != nameServer ||
		record.DirectAccessEnabled || record.DNSSecEnabled || record.DNSSecValidationRequired ||
		record.NameEncoding != "Utf8WithoutMapping" {
		return false
	}
	if configured {
		return windowsNRPTRuleNamePattern.MatchString(record.Name) &&
			record.Comment == windowsNativeDNSComment && record.DisplayName == windowsNativeDNSDisplayName
	}
	return record.Name == "" && record.Comment == "" && record.DisplayName == ""
}
