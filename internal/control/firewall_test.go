package control

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestFirewallPolicyCanonicalizesAndRendersPinnedNebulaSyntax(t *testing.T) {
	input := FirewallPolicyInput{
		Inbound: []FirewallRule{
			{Proto: "udp", Port: "53", Host: "10.42.0.53/32"},
			{Proto: "tcp", Port: "443", Group: "operators"},
			{Proto: "icmp", Port: "any", Host: "any"},
		},
		Outbound: []FirewallRule{
			{Proto: "udp", Port: "10000-10010", Host: "10.42.0.0/25"},
			{Proto: "tcp", Port: "443", Host: "10.42.0.20"},
		},
	}
	policy, err := normalizeFirewallPolicy(input, "10.42.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if policy.Mode != FirewallPolicyModeManaged || policy.RendererVersion != FirewallRendererVersionV2 || len(policy.Inbound) != 3 || policy.Inbound[0].Proto != "icmp" || policy.Inbound[2].Host != "10.42.0.53" {
		t.Fatalf("policy was not canonicalized: %#v", policy)
	}
	want := "firewall:\n" +
		"  outbound:\n" +
		"    - port: 443\n" +
		"      proto: tcp\n" +
		"      cidr: 10.42.0.20/32\n" +
		"    - port: 10000-10010\n" +
		"      proto: udp\n" +
		"      cidr: 10.42.0.0/25\n" +
		"  inbound:\n" +
		"    - port: any\n" +
		"      proto: icmp\n" +
		"      host: any\n" +
		"    - port: 443\n" +
		"      proto: tcp\n" +
		"      group: \"operators\"\n" +
		"    - port: 53\n" +
		"      proto: udp\n" +
		"      cidr: 10.42.0.53/32\n"
	if rendered := renderFirewallPolicy(policy); rendered != want {
		t.Fatalf("rendered firewall differs:\n%s\nwant:\n%s", rendered, want)
	}

	reordered := FirewallPolicyInput{
		Inbound:  []FirewallRule{input.Inbound[1], input.Inbound[2], input.Inbound[0]},
		Outbound: []FirewallRule{input.Outbound[1], input.Outbound[0]},
	}
	second, err := normalizeFirewallPolicy(reordered, "10.42.0.0/24")
	if err != nil || !sameEffectiveFirewallPolicy(policy, second) || renderFirewallPolicy(second) != want {
		t.Fatalf("input order changed canonical policy: policy=%#v err=%v", second, err)
	}

	legacy := legacyDefaultFirewallPolicy()
	legacyWant := "firewall:\n  outbound:\n    - port: any\n      proto: any\n      host: any\n  inbound:\n    - port: any\n      proto: any\n      group: all\n"
	if legacy.RendererVersion != FirewallRendererVersionV1 {
		t.Fatalf("legacy policy renderer version=%d, want v1", legacy.RendererVersion)
	}
	if rendered := renderFirewallPolicy(legacy); rendered != legacyWant {
		t.Fatalf("legacy rendering changed existing connectivity bytes: %q", rendered)
	}
}

func TestFirewallRendererV2QuotesYAMLAmbiguousGroupsAndReportsByteChanges(t *testing.T) {
	policy, err := normalizeFirewallPolicy(FirewallPolicyInput{
		Inbound: []FirewallRule{
			{Proto: "tcp", Port: "443", Group: "False"},
			{Proto: "tcp", Port: "443", Group: "null"},
			{Proto: "tcp", Port: "443", Group: "001"},
			{Proto: "tcp", Port: "443", Group: "2026-07-19"},
		},
		Outbound: []FirewallRule{},
	}, "10.42.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	policy.RendererVersion = FirewallRendererVersionV1
	legacyBytes := renderFirewallPolicy(policy)
	for _, group := range []string{"False", "null", "001", "2026-07-19"} {
		if !strings.Contains(legacyBytes, "      group: "+group+"\n") {
			t.Fatalf("v1 fixture did not reproduce bare YAML group %q:\n%s", group, legacyBytes)
		}
	}

	upgraded, bytesChanged, err := upgradeFirewallRenderer(policy)
	if err != nil {
		t.Fatal(err)
	}
	if upgraded.RendererVersion != FirewallRendererVersionV2 || !bytesChanged {
		t.Fatalf("renderer upgrade version=%d bytesChanged=%t", upgraded.RendererVersion, bytesChanged)
	}
	if policy.RendererVersion != FirewallRendererVersionV1 {
		t.Fatal("renderer upgrade mutated its input")
	}
	rendered := renderFirewallPolicy(upgraded)
	for _, group := range []string{"False", "null", "001", "2026-07-19"} {
		if !strings.Contains(rendered, "      group: \""+group+"\"\n") {
			t.Fatalf("v2 renderer did not quote YAML-ambiguous group %q:\n%s", group, rendered)
		}
		if strings.Contains(rendered, "      group: "+group+"\n") {
			t.Fatalf("v2 renderer retained bare YAML-ambiguous group %q:\n%s", group, rendered)
		}
	}

	noGroup, err := normalizeFirewallPolicy(FirewallPolicyInput{
		Inbound:  []FirewallRule{{Proto: "tcp", Port: "443", Host: "10.42.0.10"}},
		Outbound: []FirewallRule{},
	}, "10.42.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	noGroup.RendererVersion = FirewallRendererVersionV1
	upgradedNoGroup, bytesChanged, err := upgradeFirewallRenderer(noGroup)
	if err != nil || upgradedNoGroup.RendererVersion != FirewallRendererVersionV2 || bytesChanged {
		t.Fatalf("group-free renderer upgrade=%#v bytesChanged=%t err=%v", upgradedNoGroup, bytesChanged, err)
	}

	alreadyCurrent, bytesChanged, err := upgradeFirewallRenderer(upgraded)
	if err != nil || alreadyCurrent.RendererVersion != FirewallRendererVersionV2 || bytesChanged {
		t.Fatalf("current renderer upgrade=%#v bytesChanged=%t err=%v", alreadyCurrent, bytesChanged, err)
	}
	legacyDefault, bytesChanged, err := upgradeFirewallRenderer(legacyDefaultFirewallPolicy())
	if err != nil || legacyDefault.RendererVersion != FirewallRendererVersionV1 || bytesChanged {
		t.Fatalf("legacy-default renderer upgrade=%#v bytesChanged=%t err=%v", legacyDefault, bytesChanged, err)
	}

	managedV1 := cloneFirewallPolicy(policy)
	if err := validateStoredFirewallPolicy(managedV1, "10.42.0.0/24"); err != nil {
		t.Fatalf("canonical managed v1 policy was rejected before migration: %v", err)
	}
	unsupported := cloneFirewallPolicy(upgraded)
	unsupported.RendererVersion = FirewallRendererVersionV2 + 1
	if err := validateStoredFirewallPolicy(unsupported, "10.42.0.0/24"); err == nil || !strings.Contains(err.Error(), "unsupported firewall renderer version") {
		t.Fatalf("unsupported renderer version returned %v", err)
	}
	legacyV2 := legacyDefaultFirewallPolicy()
	legacyV2.RendererVersion = FirewallRendererVersionV2
	if err := validateStoredFirewallPolicy(legacyV2, "10.42.0.0/24"); err == nil || !strings.Contains(err.Error(), "historical renderer") {
		t.Fatalf("legacy-default v2 renderer returned %v", err)
	}
}

func TestFirewallPolicyRejectsInvalidOversizeAndDuplicateEquivalentRules(t *testing.T) {
	valid := func() FirewallPolicyInput {
		return FirewallPolicyInput{
			Inbound:  []FirewallRule{{Proto: "tcp", Port: "443", Group: "operators"}},
			Outbound: []FirewallRule{},
		}
	}
	for _, test := range []struct {
		name   string
		change func(*FirewallPolicyInput)
		match  string
	}{
		{name: "missing outbound array", change: func(value *FirewallPolicyInput) { value.Outbound = nil }, match: "each be a JSON array"},
		{name: "unknown proto", change: func(value *FirewallPolicyInput) { value.Inbound[0].Proto = "sctp" }, match: "proto must be"},
		{name: "proto whitespace", change: func(value *FirewallPolicyInput) { value.Inbound[0].Proto = " tcp" }, match: "whitespace"},
		{name: "zero port", change: func(value *FirewallPolicyInput) { value.Inbound[0].Port = "0" }, match: "1 through 65535"},
		{name: "leading zero port", change: func(value *FirewallPolicyInput) { value.Inbound[0].Port = "0443" }, match: "canonical decimal"},
		{name: "descending range", change: func(value *FirewallPolicyInput) { value.Inbound[0].Port = "100-90" }, match: "ascending"},
		{name: "singleton range", change: func(value *FirewallPolicyInput) { value.Inbound[0].Port = "80-80" }, match: "more than one"},
		{name: "icmp port", change: func(value *FirewallPolicyInput) { value.Inbound[0].Proto, value.Inbound[0].Port = "icmp", "8" }, match: "icmp rules require port any"},
		{name: "missing selector", change: func(value *FirewallPolicyInput) { value.Inbound[0].Group = "" }, match: "exactly one"},
		{name: "two selectors", change: func(value *FirewallPolicyInput) { value.Inbound[0].Host = "any" }, match: "exactly one"},
		{name: "group wildcard", change: func(value *FirewallPolicyInput) { value.Inbound[0].Group = "any" }, match: "use host any"},
		{name: "bad group", change: func(value *FirewallPolicyInput) { value.Inbound[0].Group = "not valid" }, match: "certificate-group grammar"},
		{name: "hostname", change: func(value *FirewallPolicyInput) { value.Inbound[0].Group, value.Inbound[0].Host = "", "node.example" }, match: "host CIDR"},
		{name: "IPv6", change: func(value *FirewallPolicyInput) { value.Inbound[0].Group, value.Inbound[0].Host = "", "2001:db8::1" }, match: "IPv4 address"},
		{name: "noncanonical CIDR", change: func(value *FirewallPolicyInput) { value.Inbound[0].Group, value.Inbound[0].Host = "", "10.42.0.5/24" }, match: "canonical IPv4"},
		{name: "outside network", change: func(value *FirewallPolicyInput) { value.Inbound[0].Group, value.Inbound[0].Host = "", "10.43.0.1" }, match: "contained in the network"},
		{name: "wider than network", change: func(value *FirewallPolicyInput) { value.Inbound[0].Group, value.Inbound[0].Host = "", "10.42.0.0/16" }, match: "contained in the network"},
		{name: "expanded range", change: func(value *FirewallPolicyInput) { value.Inbound[0].Port = "1-16385" }, match: "port slots"},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := valid()
			test.change(&input)
			if _, err := normalizeFirewallPolicy(input, "10.42.0.0/24"); err == nil || !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), test.match) {
				t.Fatalf("invalid policy returned %v", err)
			}
		})
	}

	t.Run("rule count", func(t *testing.T) {
		input := valid()
		input.Inbound = make([]FirewallRule, maxFirewallRulesPerDirection+1)
		if _, err := normalizeFirewallPolicy(input, "10.42.0.0/24"); err == nil || !strings.Contains(err.Error(), "rule limit") {
			t.Fatalf("oversize rule list returned %v", err)
		}
	})

	t.Run("IPv4 and slash-32 duplicate", func(t *testing.T) {
		input := valid()
		input.Inbound = []FirewallRule{
			{Proto: "tcp", Port: "443", Host: "10.42.0.10"},
			{Proto: "tcp", Port: "443", Host: "10.42.0.10/32"},
		}
		if _, err := normalizeFirewallPolicy(input, "10.42.0.0/24"); err == nil || !strings.Contains(err.Error(), "duplicates an equivalent rule") {
			t.Fatalf("duplicate-equivalent rules returned %v", err)
		}
	})
}

func TestNetworkFirewallPolicyDefaultsLegacyMigrationDeepCloneAndValidation(t *testing.T) {
	service := testServiceWithIssuer(t, &countingIssuer{})
	network, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "policy-default", CIDR: "10.80.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	network.FirewallPolicy.Inbound[0].Group = "returned-value-mutation"
	document, err := service.GetFirewallPolicy(network.ID)
	if err != nil || document.Mode != FirewallPolicyModeManaged || document.RendererVersion != FirewallRendererVersionV2 || document.RenderedFirewall != renderFirewallPolicy(defaultManagedFirewallPolicy()) {
		t.Fatalf("new network did not receive an isolated existing-connectivity policy: document=%#v err=%v", document, err)
	}

	var cloned State
	if err := service.store.View(func(state State) error { cloned = state; return nil }); err != nil {
		t.Fatal(err)
	}
	cloned.Networks[0].FirewallPolicy.Inbound[0].Group = "mutated"
	if err := service.store.View(func(state State) error {
		if state.Networks[0].FirewallPolicy.Inbound[0].Group != "all" {
			t.Fatal("firewall rules escaped the store deep clone")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	err = service.store.Update(func(state *State) error {
		state.Networks[0].FirewallPolicy.Inbound[0].Group = "any"
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "invalid firewall policy") {
		t.Fatalf("invalid persisted policy mutation returned %v", err)
	}
	afterInvalid, err := service.GetFirewallPolicy(network.ID)
	if err != nil || afterInvalid.Inbound[0].Group != "all" || afterInvalid.ConfigRevision != 1 {
		t.Fatalf("invalid policy mutated state: document=%#v err=%v", afterInvalid, err)
	}

	t.Run("legacy state without policy", func(t *testing.T) {
		directory := t.TempDir()
		path := filepath.Join(directory, "state.json")
		store, err := OpenStore(path)
		if err != nil {
			t.Fatal(err)
		}
		box, err := NewSecretBox(make([]byte, 32))
		if err != nil {
			t.Fatal(err)
		}
		legacyService := NewService(store, box, &countingIssuer{})
		legacyNetwork, err := legacyService.CreateNetwork(context.Background(), CreateNetworkInput{Name: "legacy", CIDR: "10.81.0.0/24"})
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var payload map[string]any
		if err := json.Unmarshal(raw, &payload); err != nil {
			t.Fatal(err)
		}
		networks := payload["networks"].([]any)
		delete(networks[0].(map[string]any), "firewall_policy")
		raw, err = json.MarshalIndent(payload, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		reopened, err := OpenStore(path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = reopened.Close() })
		migratedService := NewService(reopened, box, &countingIssuer{})
		migrated, err := migratedService.GetFirewallPolicy(legacyNetwork.ID)
		if err != nil || migrated.Mode != FirewallPolicyModeLegacyDefault || migrated.RendererVersion != FirewallRendererVersionV1 || migrated.RenderedFirewall != renderFirewallPolicy(legacyDefaultFirewallPolicy()) {
			t.Fatalf("legacy state did not preserve historical policy: document=%#v err=%v", migrated, err)
		}
	})
}

func TestStoreDecodesMissingManagedFirewallRendererAsV1(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "state.json")
	store, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	box, err := NewSecretBox(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	service := NewService(store, box, &countingIssuer{})
	network, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "managed-v1", CIDR: "10.85.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	networks := payload["networks"].([]any)
	firewall := networks[0].(map[string]any)["firewall_policy"].(map[string]any)
	delete(firewall, "renderer_version")
	raw, err = json.MarshalIndent(payload, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	decoded, err := NewService(reopened, box, &countingIssuer{}).GetFirewallPolicy(network.ID)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Mode != FirewallPolicyModeManaged || decoded.RendererVersion != FirewallRendererVersionV1 || !strings.Contains(decoded.RenderedFirewall, "      group: all\n") {
		t.Fatalf("missing managed renderer was not decoded as exact v1: %#v", decoded)
	}
}

func TestEnsureManagedNetworksMigratesManagedV1FirewallRendererAtomically(t *testing.T) {
	service := testServiceWithIssuer(t, &countingIssuer{})
	groupNetwork, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "renderer-group", CIDR: "10.86.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	hostNetwork, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "renderer-host", CIDR: "10.87.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	hostBefore, err := service.GetFirewallPolicy(hostNetwork.ID)
	if err != nil {
		t.Fatal(err)
	}
	hostBefore, err = service.UpdateFirewallPolicy(hostNetwork.ID, UpdateFirewallPolicyInput{
		ExpectedConfigRevision: hostBefore.ConfigRevision,
		Inbound:                []FirewallRule{{Proto: "tcp", Port: "443", Host: "10.87.0.10"}},
		Outbound:               []FirewallRule{},
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := service.store.Update(func(state *State) error {
		for index := range state.Networks {
			if state.Networks[index].ID == groupNetwork.ID || state.Networks[index].ID == hostNetwork.ID {
				state.Networks[index].FirewallPolicy.RendererVersion = FirewallRendererVersionV1
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	groupV1, err := service.GetFirewallPolicy(groupNetwork.ID)
	if err != nil || groupV1.RendererVersion != FirewallRendererVersionV1 || !strings.Contains(groupV1.RenderedFirewall, "      group: all\n") {
		t.Fatalf("managed v1 group fixture=%#v err=%v", groupV1, err)
	}
	hostV1, err := service.GetFirewallPolicy(hostNetwork.ID)
	if err != nil || hostV1.RendererVersion != FirewallRendererVersionV1 {
		t.Fatalf("managed v1 host fixture=%#v err=%v", hostV1, err)
	}
	migratedAt := time.Date(2026, 7, 20, 1, 2, 3, 0, time.UTC)
	service.now = func() time.Time { return migratedAt }
	if err := service.EnsureManagedNetworks(); err != nil {
		t.Fatal(err)
	}

	groupV2, err := service.GetFirewallPolicy(groupNetwork.ID)
	if err != nil || groupV2.RendererVersion != FirewallRendererVersionV2 || groupV2.ConfigRevision != groupV1.ConfigRevision+1 || !groupV2.ConfigUpdatedAt.Equal(migratedAt) || !strings.Contains(groupV2.RenderedFirewall, "      group: \"all\"\n") {
		t.Fatalf("managed group migration=%#v err=%v", groupV2, err)
	}
	hostV2, err := service.GetFirewallPolicy(hostNetwork.ID)
	if err != nil || hostV2.RendererVersion != FirewallRendererVersionV2 || hostV2.ConfigRevision != hostV1.ConfigRevision || !hostV2.ConfigUpdatedAt.Equal(hostV1.ConfigUpdatedAt) || hostV2.RenderedFirewall != hostV1.RenderedFirewall {
		t.Fatalf("group-free migration changed signed config identity: before=%#v after=%#v err=%v", hostV1, hostV2, err)
	}

	migrations := 0
	if err := service.store.View(func(state State) error {
		for _, event := range state.Audit {
			if event.Action != "network.firewall_renderer_migrated" {
				continue
			}
			migrations++
			if event.ResourceID != groupNetwork.ID || event.Details["from_renderer_version"] != FirewallRendererVersionV1 || event.Details["to_renderer_version"] != FirewallRendererVersionV2 || event.Details["rendered_bytes_changed"] != true || event.Details["old_sha256"] != ConfigDigest(groupV1.RenderedFirewall) || event.Details["new_sha256"] != ConfigDigest(groupV2.RenderedFirewall) || event.Details["previous_config_revision"] != groupV1.ConfigRevision || event.Details["config_revision"] != groupV2.ConfigRevision {
				t.Fatalf("renderer migration audit=%#v", event)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if migrations != 1 {
		t.Fatalf("renderer migration audit count=%d, want 1", migrations)
	}
	if err := service.EnsureManagedNetworks(); err != nil {
		t.Fatal(err)
	}
	afterRetry, err := service.GetFirewallPolicy(groupNetwork.ID)
	if err != nil || afterRetry.ConfigRevision != groupV2.ConfigRevision || !afterRetry.ConfigUpdatedAt.Equal(groupV2.ConfigUpdatedAt) {
		t.Fatalf("renderer migration retry changed config identity: %#v err=%v", afterRetry, err)
	}
	afterRetryMigrations := 0
	_ = service.store.View(func(state State) error {
		for _, event := range state.Audit {
			if event.Action == "network.firewall_renderer_migrated" {
				afterRetryMigrations++
			}
		}
		return nil
	})
	if afterRetryMigrations != migrations {
		t.Fatalf("renderer migration retry appended another audit event: %d", afterRetryMigrations)
	}
}

func TestEnsureManagedNetworksRendererMigrationPreservesLegacyAndRollsBackAtRevisionExhaustion(t *testing.T) {
	service := testServiceWithIssuer(t, &countingIssuer{})
	legacy, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "renderer-legacy", CIDR: "10.88.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	exhausted, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "renderer-exhausted", CIDR: "10.89.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.store.Update(func(state *State) error {
		for index := range state.Networks {
			switch state.Networks[index].ID {
			case legacy.ID:
				state.Networks[index].FirewallPolicy = legacyDefaultFirewallPolicy()
			case exhausted.ID:
				state.Networks[index].FirewallPolicy.RendererVersion = FirewallRendererVersionV1
				state.Networks[index].ConfigRevision = math.MaxInt64
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	legacyBefore, _ := service.GetFirewallPolicy(legacy.ID)
	exhaustedBefore, _ := service.GetFirewallPolicy(exhausted.ID)
	if err := service.EnsureManagedNetworks(); err == nil || !errors.Is(err, ErrConflict) {
		t.Fatalf("exhausted renderer migration returned %v", err)
	}
	legacyAfter, _ := service.GetFirewallPolicy(legacy.ID)
	exhaustedAfter, _ := service.GetFirewallPolicy(exhausted.ID)
	if legacyAfter.RendererVersion != FirewallRendererVersionV1 || legacyAfter.RenderedFirewall != legacyBefore.RenderedFirewall || legacyAfter.ConfigRevision != legacyBefore.ConfigRevision {
		t.Fatalf("legacy default changed during failed migration: before=%#v after=%#v", legacyBefore, legacyAfter)
	}
	if exhaustedAfter.RendererVersion != FirewallRendererVersionV1 || exhaustedAfter.ConfigRevision != exhaustedBefore.ConfigRevision || exhaustedAfter.RenderedFirewall != exhaustedBefore.RenderedFirewall {
		t.Fatalf("exhausted migration did not roll back: before=%#v after=%#v", exhaustedBefore, exhaustedAfter)
	}
}

func TestFirewallPolicyPreviewUpdateIdempotencyAndSignedConfigPropagation(t *testing.T) {
	now := time.Date(2026, 7, 19, 20, 0, 0, 0, time.UTC)
	issuer := &countingIssuer{now: func() time.Time { return now }}
	service := testServiceWithIssuer(t, issuer)
	service.now = func() time.Time { return now }
	network, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "policy", CIDR: "10.82.0.0/24", CertificateTTL: 24})
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.CreateNode(network.ID, CreateNodeInput{Name: "node-01", Groups: []string{"operators"}})
	if err != nil {
		t.Fatal(err)
	}
	agentToken := strings.Repeat("p", 42) + "A"
	publicKey := testNebulaPublicKey('A')
	bundle, err := service.Enroll(context.Background(), created.EnrollmentToken, publicKey, HashToken(agentToken))
	if err != nil {
		t.Fatal(err)
	}
	var before State
	_ = service.store.View(func(state State) error { before = state; return nil })
	now = now.Add(time.Minute)
	input := FirewallPolicyInput{
		Inbound: []FirewallRule{
			{Proto: "udp", Port: "53", Host: "10.82.0.53"},
			{Proto: "tcp", Port: "443", Group: "operators"},
		},
		Outbound: []FirewallRule{},
	}
	preview, err := service.PreviewFirewallPolicy(network.ID, input)
	if err != nil || !preview.WouldChange || preview.ConfigRevision != 1 || preview.ProposedConfigRevision != 2 || !strings.HasPrefix(preview.RenderedFirewall, "firewall:\n") {
		t.Fatalf("unexpected preview: preview=%#v err=%v", preview, err)
	}
	updated, err := service.UpdateFirewallPolicy(network.ID, UpdateFirewallPolicyInput{
		ExpectedConfigRevision: 1, Inbound: input.Inbound, Outbound: input.Outbound,
	})
	if err != nil || updated.ConfigRevision != 2 || !updated.ConfigUpdatedAt.Equal(now) || updated.Mode != FirewallPolicyModeManaged {
		t.Fatalf("unexpected update: document=%#v err=%v", updated, err)
	}

	managed, err := service.AgentConfig(agentToken)
	if err != nil {
		t.Fatal(err)
	}
	if managed.Revision != 2 || managed.SHA256 == bundle.ConfigSHA256 || managed.Signature == bundle.ConfigSignature || !strings.Contains(managed.Config, updated.RenderedFirewall) {
		t.Fatalf("firewall update did not propagate to signed config: config=%#v", managed)
	}
	if err := VerifyConfig(network.ConfigSigningPublicKey, managed.SignatureMetadata(), managed.Config, managed.SHA256, managed.Signature); err != nil {
		t.Fatalf("updated desired config signature failed: %v", err)
	}

	var after State
	_ = service.store.View(func(state State) error { after = state; return nil })
	if len(after.Audit) != len(before.Audit)+1 {
		t.Fatalf("policy update appended %d audit events, want one", len(after.Audit)-len(before.Audit))
	}
	event := after.Audit[len(after.Audit)-1]
	oldHash, oldOK := event.Details["old_sha256"].(string)
	newHash, newOK := event.Details["new_sha256"].(string)
	if event.Action != "network.firewall_policy_updated" || event.ResourceID != network.ID || !oldOK || !newOK || len(oldHash) != 64 || len(newHash) != 64 || oldHash == newHash || event.Details["config_revision"] != int64(2) {
		t.Fatalf("unsafe or incomplete policy audit event: %#v", event)
	}

	retry, err := service.UpdateFirewallPolicy(network.ID, UpdateFirewallPolicyInput{
		ExpectedConfigRevision: 1,
		Inbound:                []FirewallRule{input.Inbound[1], input.Inbound[0]}, Outbound: []FirewallRule{},
	})
	if err != nil || retry.ConfigRevision != 2 || !retry.ConfigUpdatedAt.Equal(updated.ConfigUpdatedAt) {
		t.Fatalf("stale same-payload retry was not idempotent: document=%#v err=%v", retry, err)
	}
	unchangedPreview, err := service.PreviewFirewallPolicy(network.ID, input)
	if err != nil || unchangedPreview.WouldChange || unchangedPreview.ConfigRevision != 2 || unchangedPreview.ProposedConfigRevision != 2 {
		t.Fatalf("unchanged preview was not idempotent: preview=%#v err=%v", unchangedPreview, err)
	}

	invalid := FirewallPolicyInput{Inbound: []FirewallRule{{Proto: "tcp", Port: "80", Host: "10.83.0.1"}}, Outbound: []FirewallRule{}}
	if _, err := service.UpdateFirewallPolicy(network.ID, UpdateFirewallPolicyInput{ExpectedConfigRevision: 2, Inbound: invalid.Inbound, Outbound: invalid.Outbound}); err == nil || !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid update returned %v", err)
	}
	different := FirewallPolicyInput{Inbound: []FirewallRule{{Proto: "tcp", Port: "80", Host: "10.82.0.10"}}, Outbound: []FirewallRule{}}
	if _, err := service.UpdateFirewallPolicy(network.ID, UpdateFirewallPolicyInput{ExpectedConfigRevision: 1, Inbound: different.Inbound, Outbound: different.Outbound}); err == nil || !errors.Is(err, ErrConflict) {
		t.Fatalf("stale overwrite returned %v", err)
	}
	final, err := service.GetFirewallPolicy(network.ID)
	if err != nil || final.ConfigRevision != 2 || !slices.Equal(final.Inbound, updated.Inbound) {
		t.Fatalf("failed update mutated policy: document=%#v err=%v", final, err)
	}
	var finalState State
	_ = service.store.View(func(state State) error { finalState = state; return nil })
	if len(finalState.Audit) != len(after.Audit) {
		t.Fatal("invalid, stale, or idempotent update appended an audit event")
	}
}

func TestConcurrentFirewallPolicyUpdatesRejectStaleOverwriteAndRetryWinner(t *testing.T) {
	service := testServiceWithIssuer(t, &countingIssuer{})
	network, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "policy-race", CIDR: "10.84.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	inputs := []UpdateFirewallPolicyInput{
		{ExpectedConfigRevision: 1, Inbound: []FirewallRule{{Proto: "tcp", Port: "443", Host: "10.84.0.10"}}, Outbound: []FirewallRule{}},
		{ExpectedConfigRevision: 1, Inbound: []FirewallRule{{Proto: "udp", Port: "53", Host: "10.84.0.53"}}, Outbound: []FirewallRule{}},
	}
	type updateResult struct {
		index    int
		document FirewallPolicyDocument
		err      error
	}
	start := make(chan struct{})
	results := make(chan updateResult, len(inputs))
	var wait sync.WaitGroup
	for index, input := range inputs {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			document, err := service.UpdateFirewallPolicy(network.ID, input)
			results <- updateResult{index: index, document: document, err: err}
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	winner := -1
	conflicts := 0
	for result := range results {
		switch {
		case result.err == nil:
			winner = result.index
			if result.document.ConfigRevision != 2 {
				t.Fatalf("winner revision=%d", result.document.ConfigRevision)
			}
		case errors.Is(result.err, ErrConflict):
			conflicts++
		default:
			t.Fatalf("unexpected concurrent update error: %v", result.err)
		}
	}
	if winner < 0 || conflicts != 1 {
		t.Fatalf("concurrent results winner=%d conflicts=%d", winner, conflicts)
	}
	retry, err := service.UpdateFirewallPolicy(network.ID, inputs[winner])
	if err != nil || retry.ConfigRevision != 2 {
		t.Fatalf("lost-response retry failed: document=%#v err=%v", retry, err)
	}
	var state State
	_ = service.store.View(func(snapshot State) error { state = snapshot; return nil })
	policyEvents := 0
	for _, event := range state.Audit {
		if event.Action == "network.firewall_policy_updated" {
			policyEvents++
		}
	}
	if policyEvents != 1 {
		t.Fatalf("concurrent update and retry wrote %d policy events", policyEvents)
	}
}
