//go:build postgresmaxdocgate

package control

import (
	"bytes"
	"context"
	"testing"
	"time"
)

func TestBuildMaximumDocumentFixtureUsesBoundedGraphAndWhitespace(t *testing.T) {
	fixture, err := BuildMaximumDocumentFixture(context.Background(), MaximumDocumentFixtureOptions{
		Directory: t.TempDir(), MasterKey: bytes.Repeat([]byte{0x31}, 32),
		AdminToken:            bytes.Repeat([]byte{'A'}, 43),
		At:                    time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC),
		CanonicalMinimumBytes: 1 << 20, CanonicalMaximumBytes: 1536 << 10, ExactBytes: 2 << 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(fixture.CanonicalBytes) < 1<<20 || len(fixture.CanonicalBytes) > 1536<<10 || len(fixture.ExactBytes) != 2<<20 {
		t.Fatalf("fixture sizes canonical=%d exact=%d", len(fixture.CanonicalBytes), len(fixture.ExactBytes))
	}
	if fixture.NodeCount < 1 || fixture.EnrollmentCount != fixture.NodeCount || fixture.AuditCount != fixture.NodeCount+maximumDocumentFixtureBaselineAuditCount {
		t.Fatalf("fixture counts nodes=%d enrollments=%d audits=%d, want audits=%d", fixture.NodeCount, fixture.EnrollmentCount, fixture.AuditCount, fixture.NodeCount+maximumDocumentFixtureBaselineAuditCount)
	}
	if fixture.NetworkCount != 1 || fixture.NetworkCIDR != "10.240.0.0/16" || fixture.GroupCount != 64 || fixture.InboundRuleCount != 128 || fixture.OutboundRuleCount != 128 {
		t.Fatalf("fixture bounded shape=%+v", fixture)
	}
	if !bytes.Equal(fixture.ExactBytes[:len(fixture.CanonicalBytes)], fixture.CanonicalBytes) {
		t.Fatal("exact document does not preserve canonical prefix")
	}
	if suffix := fixture.ExactBytes[len(fixture.CanonicalBytes):]; len(bytes.Trim(suffix, " ")) != 0 {
		t.Fatal("exact document contains non-whitespace padding")
	}
	box, err := NewSecretBox(bytes.Repeat([]byte{0x31}, 32))
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := CanonicalizeMaximumDocumentRecoverySnapshot(fixture.ExactBytes, box)
	if err != nil || !bytes.Equal(canonical, fixture.CanonicalBytes) {
		t.Fatalf("canonicalize exact fixture: equal=%t err=%v", bytes.Equal(canonical, fixture.CanonicalBytes), err)
	}
	t.Logf("canonical_bytes=%d exact_bytes=%d nodes=%d padding_bytes=%d", len(fixture.CanonicalBytes), len(fixture.ExactBytes), fixture.NodeCount, len(fixture.ExactBytes)-len(fixture.CanonicalBytes))
}

func TestMaximumDocumentControlHardLimitPlusOneIsRejected(t *testing.T) {
	box, err := NewSecretBox(bytes.Repeat([]byte{0x31}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateRecoverySnapshot(make([]byte, MaximumDocumentControlBytes+1), box); err == nil {
		t.Fatal("control hard limit plus one was accepted")
	}
}
