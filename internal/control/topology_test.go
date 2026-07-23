package control

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

func bindAndMigrateTopology(t *testing.T, service *Service) {
	t.Helper()
	master := make([]byte, 32)
	masterVerifier, err := DeriveMasterKeyVerifier(master)
	if err != nil {
		t.Fatal(err)
	}
	adminVerifier, err := DeriveAdminCredentialVerifier(master, bytes.Repeat([]byte{'T'}, 43))
	if err != nil {
		t.Fatal(err)
	}
	if err := service.EnsureRecoveryCredentialBinding(masterVerifier, adminVerifier, false); err != nil {
		t.Fatal(err)
	}
	if err := service.EnsureTopologySchema(); err != nil {
		t.Fatal(err)
	}
}

func TestEnsureTopologySchemaMigratesWithoutInventingPlacement(t *testing.T) {
	service := testServiceWithIssuer(t, &countingIssuer{})
	network, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "topology", CIDR: "10.93.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.CreateNode(network.ID, CreateNodeInput{Name: "legacy-node"})
	if err != nil {
		t.Fatal(err)
	}
	if created.Node.Site != "" || created.Node.FailureDomain != "" {
		t.Fatalf("pre-v3 node unexpectedly has topology: %#v", created.Node)
	}
	bindAndMigrateTopology(t, service)

	var migrated State
	if err := service.store.View(func(state State) error { migrated = state; return nil }); err != nil {
		t.Fatal(err)
	}
	if migrated.Version != ControlStateVersionTopology || len(migrated.Nodes) != 1 || migrated.Nodes[0].Site != UnassignedTopologyLabel || migrated.Nodes[0].FailureDomain != UnassignedTopologyLabel {
		t.Fatalf("unexpected migrated topology state: %#v", migrated)
	}
	last := migrated.Audit[len(migrated.Audit)-1]
	if last.Action != "control.topology_schema_migrated" || last.Details["from_version"] != float64(ControlStateVersionCredentialBinding) && last.Details["from_version"] != ControlStateVersionCredentialBinding || last.Details["to_version"] != float64(ControlStateVersionTopology) && last.Details["to_version"] != ControlStateVersionTopology {
		t.Fatalf("unexpected topology migration audit: %#v", last)
	}
	before, err := os.Stat(service.store.path)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.EnsureTopologySchema(); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(service.store.path)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) {
		t.Fatal("idempotent topology migration rewrote the state file")
	}
}

func TestCreateNodeNormalizesTopologySeparatelyFromSecurityGroups(t *testing.T) {
	service := testServiceWithIssuer(t, &countingIssuer{})
	bindAndMigrateTopology(t, service)
	network, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "placed", CIDR: "10.94.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.CreateNode(network.ID, CreateNodeInput{
		Name: "placed-node", Site: " AWS-USE1 ", FailureDomain: " AZ-A ", Groups: []string{"servers"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if created.Node.Site != "aws-use1" || created.Node.FailureDomain != "az-a" || strings.Join(created.Node.Groups, ",") != "all,servers" {
		t.Fatalf("topology or groups were not independently normalized: %#v", created.Node)
	}
	defaulted, err := service.CreateNode(network.ID, CreateNodeInput{Name: "unplaced-node"})
	if err != nil {
		t.Fatal(err)
	}
	if defaulted.Node.Site != UnassignedTopologyLabel || defaulted.Node.FailureDomain != UnassignedTopologyLabel {
		t.Fatalf("omitted placement was not explicit: %#v", defaulted.Node)
	}
}

func TestCreateNodeRejectsInvalidOrPrematureTopologyWithoutMutation(t *testing.T) {
	service := testServiceWithIssuer(t, &countingIssuer{})
	network, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "legacy", CIDR: "10.95.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.CreateNode(network.ID, CreateNodeInput{Name: "premature", Site: "site-a", FailureDomain: "zone-a"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("pre-v3 topology error=%v, want conflict", err)
	}
	bindAndMigrateTopology(t, service)
	before, err := os.ReadFile(service.store.path)
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range []CreateNodeInput{
		{Name: "bad-space", Site: "site a", FailureDomain: "zone-a"},
		{Name: "bad-slash", Site: "site-a", FailureDomain: "zone/a"},
		{Name: "bad-long", Site: strings.Repeat("s", 64), FailureDomain: "zone-a"},
	} {
		if _, err := service.CreateNode(network.ID, input); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid topology %#v error=%v, want invalid", input, err)
		}
	}
	after, err := os.ReadFile(service.store.path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("invalid topology mutated control state")
	}
}

func TestTopologyMigrationUpdatesDetachedRecoveryReplayNode(t *testing.T) {
	service, before := boundedRecoveryResultState(t)
	if before.AgentRecoveries[0].Result.Node.Site != "" {
		t.Fatal("pre-v3 recovery result unexpectedly has placement")
	}
	bindAndMigrateTopology(t, service)
	var after State
	if err := service.store.View(func(state State) error { after = state; return nil }); err != nil {
		t.Fatal(err)
	}
	result := after.AgentRecoveries[0].Result
	if result == nil || result.Node.Site != UnassignedTopologyLabel || result.Node.FailureDomain != UnassignedTopologyLabel {
		t.Fatalf("recovery replay node was not migrated: %#v", result)
	}
}

func TestUpdateNodeTopologyIsAuditedWithoutChangingSignedConfig(t *testing.T) {
	service := testServiceWithIssuer(t, &countingIssuer{})
	bindAndMigrateTopology(t, service)
	network, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "move", CIDR: "10.97.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.CreateNode(network.ID, CreateNodeInput{Name: "movable", Site: "site-a", FailureDomain: "rack-a"})
	if err != nil {
		t.Fatal(err)
	}
	updated, err := service.UpdateNodeTopology(created.Node.ID, UpdateNodeTopologyInput{Site: " SITE-B ", FailureDomain: " RACK-B "})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Site != "site-b" || updated.FailureDomain != "rack-b" {
		t.Fatalf("unexpected updated topology: %#v", updated)
	}
	networks, err := service.Networks()
	if err != nil || len(networks) != 1 || networks[0].ConfigRevision != network.ConfigRevision {
		t.Fatalf("placement update changed signed config revision: networks=%#v err=%v", networks, err)
	}
	audit, err := service.Audit(100)
	if err != nil {
		t.Fatal(err)
	}
	var topologyAudit AuditEvent
	for _, event := range audit {
		if event.Action == "node.topology_updated" {
			topologyAudit = event
			break
		}
	}
	if topologyAudit.Action == "" || topologyAudit.ResourceID != created.Node.ID || topologyAudit.Details["old_site"] != "site-a" || topologyAudit.Details["site"] != "site-b" || topologyAudit.Details["old_failure_domain"] != "rack-a" || topologyAudit.Details["failure_domain"] != "rack-b" {
		t.Fatalf("unexpected topology audit: %#v", topologyAudit)
	}
	before, err := os.Stat(service.store.path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.UpdateNodeTopology(created.Node.ID, UpdateNodeTopologyInput{Site: "site-b", FailureDomain: "rack-b"}); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(service.store.path)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) {
		t.Fatal("idempotent topology update rewrote control state")
	}
	if _, err := service.RevokeNode(created.Node.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.UpdateNodeTopology(created.Node.ID, UpdateNodeTopologyInput{Site: "site-c", FailureDomain: "rack-c"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("revoked topology update error=%v, want conflict", err)
	}
}
