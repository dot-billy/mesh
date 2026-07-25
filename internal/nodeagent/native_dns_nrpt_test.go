package nodeagent

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"testing"

	"mesh/internal/control"
)

const testWindowsNRPTRuleName = "{01234567-89ab-cdef-0123-456789abcdef}"

type fakeWindowsNRPTBackend struct {
	rules                []windowsNRPTRecord
	addCalls             int
	removeCalls          int
	failAddBefore        map[string]bool
	failAddAfter         map[string]bool
	failRemoveAfter      bool
	omitEffective        bool
	wrongEffectiveServer bool
}

func (backend *fakeWindowsNRPTBackend) Inspect(context.Context) (windowsNRPTSnapshot, error) {
	configured := append([]windowsNRPTRecord(nil), backend.rules...)
	effective := make([]windowsNRPTRecord, 0, len(configured))
	if !backend.omitEffective {
		for _, rule := range configured {
			copy := rule
			copy.Name = ""
			copy.Comment = ""
			copy.DisplayName = ""
			if backend.wrongEffectiveServer {
				copy.NameServers = []string{"10.99.0.99"}
			}
			effective = append(effective, copy)
		}
	}
	return windowsNRPTSnapshot{Configured: configured, Effective: effective}, nil
}

func (backend *fakeWindowsNRPTBackend) Add(_ context.Context, namespace, nameServer string) error {
	backend.addCalls++
	if backend.failAddBefore[namespace] {
		return errors.New("injected add failure")
	}
	backend.rules = append(backend.rules, exactTestWindowsNRPTRule(testWindowsNRPTRuleName, namespace, nameServer))
	if backend.failAddAfter[namespace] {
		return errors.New("injected response loss")
	}
	return nil
}

func (backend *fakeWindowsNRPTBackend) Remove(_ context.Context, name string) error {
	backend.removeCalls++
	for index, rule := range backend.rules {
		if rule.Name == name {
			backend.rules = append(backend.rules[:index], backend.rules[index+1:]...)
			if backend.failRemoveAfter {
				return errors.New("injected remove response loss")
			}
			return nil
		}
	}
	return errors.New("rule is absent")
}

type fakeWindowsNativeDNSProxy struct {
	port   int
	closed int
}

func (proxy *fakeWindowsNativeDNSProxy) Port() int    { return proxy.port }
func (proxy *fakeWindowsNativeDNSProxy) Close() error { proxy.closed++; return nil }

func TestWindowsNativeDNSManagerReconcilesAndCleansPersistentRule(t *testing.T) {
	backend := &fakeWindowsNRPTBackend{}
	var proxies []*fakeWindowsNativeDNSProxy
	manager := &windowsNativeDNSManager{
		backend: backend,
		startProxy: func(_ control.NativeDNSPolicy, port int) (nativeDNSProxyHandle, error) {
			proxy := &fakeWindowsNativeDNSProxy{port: port}
			proxies = append(proxies, proxy)
			return proxy, nil
		},
	}
	config := windowsNativeDNSSignedConfig(t, windowsNativeDNSTestPolicy("corp.mesh", "10.150.0.9"))
	if err := manager.Reconcile(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	if len(proxies) != 1 || proxies[0].port != 53 || backend.addCalls != 1 || manager.active == nil {
		t.Fatalf("activation = proxies:%d port:%d adds:%d active:%v", len(proxies), proxies[0].port, backend.addCalls, manager.active != nil)
	}
	if err := manager.Reconcile(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	if len(proxies) != 1 || backend.addCalls != 1 {
		t.Fatal("idempotent reconciliation restarted or recreated native DNS")
	}
	if err := manager.Disable(context.Background()); err != nil {
		t.Fatal(err)
	}
	if proxies[0].closed != 1 || len(backend.rules) != 0 || manager.active != nil {
		t.Fatal("disable did not close the adapter and remove the persistent NRPT rule")
	}
}

func TestWindowsNativeDNSManagerAdoptsResponseLossAndRemovesRestartOrphan(t *testing.T) {
	policy := windowsNativeDNSTestPolicy("corp.mesh", "10.150.0.9")
	backend := &fakeWindowsNRPTBackend{failAddAfter: map[string]bool{".corp.mesh": true}}
	manager := testWindowsNativeDNSManager(backend)
	if err := manager.Reconcile(context.Background(), windowsNativeDNSSignedConfig(t, policy)); err != nil {
		t.Fatalf("response-loss add was not adopted: %v", err)
	}
	if manager.active == nil || len(backend.rules) != 1 {
		t.Fatal("response-loss activation was not retained")
	}

	orphanBackend := &fakeWindowsNRPTBackend{rules: []windowsNRPTRecord{exactTestWindowsNRPTRule(testWindowsNRPTRuleName, ".old.mesh", "10.140.0.9")}}
	orphanManager := testWindowsNativeDNSManager(orphanBackend)
	if err := orphanManager.Disable(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(orphanBackend.rules) != 0 || orphanBackend.removeCalls != 1 {
		t.Fatal("restart cleanup did not remove the exact Mesh-owned orphan")
	}
	responseLossBackend := &fakeWindowsNRPTBackend{
		rules:           []windowsNRPTRecord{exactTestWindowsNRPTRule(testWindowsNRPTRuleName, ".old.mesh", "10.140.0.9")},
		failRemoveAfter: true,
	}
	responseLossManager := &windowsNativeDNSManager{backend: responseLossBackend}
	if err := responseLossManager.Disable(context.Background()); err != nil {
		t.Fatalf("remove response loss was not adopted: %v", err)
	}
	if len(responseLossBackend.rules) != 0 {
		t.Fatal("response-loss cleanup left a persistent NRPT rule")
	}
}

func TestWindowsNativeDNSManagerRejectsForeignNamespaceWithoutMutation(t *testing.T) {
	foreign := exactTestWindowsNRPTRule("{11111111-2222-3333-4444-555555555555}", ".corp.mesh", "10.99.0.2")
	foreign.Comment = "administrator policy"
	foreign.DisplayName = "Corporate DNS"
	backend := &fakeWindowsNRPTBackend{rules: []windowsNRPTRecord{foreign}}
	manager := testWindowsNativeDNSManager(backend)
	err := manager.Reconcile(context.Background(), windowsNativeDNSSignedConfig(t, windowsNativeDNSTestPolicy("corp.mesh", "10.150.0.9")))
	if err == nil {
		t.Fatal("foreign NRPT namespace owner was accepted")
	}
	if backend.addCalls != 0 || backend.removeCalls != 0 || len(backend.rules) != 1 {
		t.Fatal("foreign NRPT policy was mutated")
	}
}

func TestWindowsNativeDNSManagerFailsClosedOnEffectiveDrift(t *testing.T) {
	backend := &fakeWindowsNRPTBackend{wrongEffectiveServer: true}
	manager := testWindowsNativeDNSManager(backend)
	err := manager.Reconcile(context.Background(), windowsNativeDNSSignedConfig(t, windowsNativeDNSTestPolicy("corp.mesh", "10.150.0.9")))
	if err == nil {
		t.Fatal("effective NRPT drift was accepted")
	}
	if len(backend.rules) != 0 || backend.removeCalls != 1 || len(manager.testProxies()) != 1 || manager.testProxies()[0].closed != 1 {
		t.Fatal("failed activation did not close its proxy and remove its rule")
	}
}

func TestWindowsNativeDNSManagerRestoresPriorPolicyAfterUpdateFailure(t *testing.T) {
	backend := &fakeWindowsNRPTBackend{failAddBefore: map[string]bool{".next.mesh": true}}
	manager := testWindowsNativeDNSManager(backend)
	prior := windowsNativeDNSTestPolicy("corp.mesh", "10.150.0.9")
	if err := manager.Reconcile(context.Background(), windowsNativeDNSSignedConfig(t, prior)); err != nil {
		t.Fatal(err)
	}
	next := windowsNativeDNSTestPolicy("next.mesh", "10.150.0.9")
	if err := manager.Reconcile(context.Background(), windowsNativeDNSSignedConfig(t, next)); err == nil {
		t.Fatal("injected update failure was hidden")
	}
	if manager.active == nil || !reflect.DeepEqual(manager.active.policy, prior) || len(backend.rules) != 1 || backend.rules[0].Namespaces[0] != ".corp.mesh" {
		t.Fatal("previous signed Windows native DNS policy was not restored")
	}
}

func testWindowsNativeDNSManager(backend *fakeWindowsNRPTBackend) *windowsNativeDNSManager {
	manager := &windowsNativeDNSManager{backend: backend}
	manager.startProxy = func(_ control.NativeDNSPolicy, port int) (nativeDNSProxyHandle, error) {
		proxy := &fakeWindowsNativeDNSProxy{port: port}
		testWindowsNativeDNSProxies[manager] = append(testWindowsNativeDNSProxies[manager], proxy)
		return proxy, nil
	}
	return manager
}

var testWindowsNativeDNSProxies = map[*windowsNativeDNSManager][]*fakeWindowsNativeDNSProxy{}

func (manager *windowsNativeDNSManager) testProxies() []*fakeWindowsNativeDNSProxy {
	return testWindowsNativeDNSProxies[manager]
}

func exactTestWindowsNRPTRule(name, namespace, server string) windowsNRPTRecord {
	return windowsNRPTRecord{
		Comment: windowsNativeDNSComment, DisplayName: windowsNativeDNSDisplayName,
		Name: name, NameEncoding: "Utf8WithoutMapping",
		Namespaces: []string{namespace}, NameServers: []string{server},
	}
}

func windowsNativeDNSTestPolicy(domain, localIP string) control.NativeDNSPolicy {
	resolvers := []control.NativeDNSResolver{{IP: "10.150.0.2", Port: 5353}, {IP: "10.150.0.3", Port: 5353}}
	sort.Slice(resolvers, func(left, right int) bool { return resolvers[left].IP < resolvers[right].IP })
	return control.NativeDNSPolicy{
		Schema: control.NativeDNSPolicySchema, LocalIP: localIP, NetworkCIDR: "10.150.0.0/24",
		SearchDomain: domain, Resolvers: resolvers,
	}
}

func windowsNativeDNSSignedConfig(t *testing.T, policy control.NativeDNSPolicy) string {
	t.Helper()
	raw, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	return control.NativeDNSPolicyPrefix + base64.RawURLEncoding.EncodeToString(raw) + "\npki:\n"
}
