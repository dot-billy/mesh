package control

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestEnrollmentPreflightIsTokenScopedReadOnlyAndDoesNotConsumeEnrollment(t *testing.T) {
	now := time.Date(2026, 7, 21, 2, 0, 0, 0, time.UTC)
	service := testServiceWithIssuer(t, &countingIssuer{now: func() time.Time { return now }})
	service.now = func() time.Time { return now }
	network, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "future-site", CIDR: "10.230.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.CreateNode(network.ID, CreateNodeInput{Name: "first-lighthouse", Role: "lighthouse", PublicEndpoint: "LH.Example.:4242"})
	if err != nil {
		t.Fatal(err)
	}
	before, err := service.Audit(100)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := service.PreflightEnrollment(created.EnrollmentToken)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Schema != EnrollmentPreflightSchemaV1 || plan.TargetRole != "lighthouse" || plan.NetworkCIDR != network.CIDR ||
		!reflect.DeepEqual(plan.LighthouseEndpoints, []string{"LH.Example.:4242"}) || !plan.TokenExpiresAt.Equal(created.ExpiresAt) {
		t.Fatalf("unexpected preflight plan: %#v", plan)
	}
	after, err := service.Audit(100)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(after, before) {
		t.Fatal("enrollment preflight mutated audit history")
	}
	if _, err := service.Enroll(context.Background(), created.EnrollmentToken, testNebulaPublicKey('P'), HashToken(strings.Repeat("p", 42)+"A")); err != nil {
		t.Fatalf("preflight consumed the enrollment credential: %v", err)
	}
	if _, err := service.PreflightEnrollment(created.EnrollmentToken); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("used credential preflight returned %v", err)
	}
}

func TestEnrollmentPreflightProjectsActiveLighthousesAndRejectsInvalidCredentials(t *testing.T) {
	now := time.Date(2026, 7, 21, 3, 0, 0, 0, time.UTC)
	service := testServiceWithIssuer(t, &countingIssuer{now: func() time.Time { return now }})
	service.now = func() time.Time { return now }
	network, err := service.CreateNetwork(context.Background(), CreateNetworkInput{Name: "future-member", CIDR: "10.231.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	first, err := service.CreateNode(network.ID, CreateNodeInput{Name: "alpha", Role: "lighthouse", PublicEndpoint: "198.51.100.2:4242"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Enroll(context.Background(), first.EnrollmentToken, testNebulaPublicKey('Q'), HashToken(strings.Repeat("q", 42)+"A")); err != nil {
		t.Fatal(err)
	}
	second, err := service.CreateNode(network.ID, CreateNodeInput{Name: "beta", Role: "lighthouse", PublicEndpoint: "z.example:4242"})
	if err != nil {
		t.Fatal(err)
	}
	member, err := service.CreateNode(network.ID, CreateNodeInput{Name: "member"})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := service.PreflightEnrollment(member.EnrollmentToken)
	if err != nil {
		t.Fatal(err)
	}
	if plan.TargetRole != "member" || !reflect.DeepEqual(plan.LighthouseEndpoints, []string{"198.51.100.2:4242"}) {
		t.Fatalf("pending lighthouse leaked into member plan: %#v", plan)
	}
	lighthousePlan, err := service.PreflightEnrollment(second.EnrollmentToken)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(lighthousePlan.LighthouseEndpoints, []string{"198.51.100.2:4242", "z.example:4242"}) {
		t.Fatalf("target lighthouse was not projected: %#v", lighthousePlan)
	}
	if _, err := service.PreflightEnrollment(strings.Repeat("x", 43)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("unknown credential returned %v", err)
	}
	service.now = func() time.Time { return member.ExpiresAt.Add(time.Second) }
	if _, err := service.PreflightEnrollment(member.EnrollmentToken); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expired credential returned %v", err)
	}
}

func TestValidateEnrollmentPreflightRejectsNoncanonicalPlans(t *testing.T) {
	valid := EnrollmentPreflight{
		Schema: EnrollmentPreflightSchemaV1, TargetRole: "member", NetworkCIDR: "10.232.0.0/24",
		LighthouseEndpoints: []string{"198.51.100.1:4242", "lh.example:4242"},
		TokenExpiresAt:      time.Date(2026, 7, 21, 4, 0, 0, 0, time.UTC),
	}
	if err := ValidateEnrollmentPreflight(valid); err != nil {
		t.Fatal(err)
	}
	tests := []func(*EnrollmentPreflight){
		func(value *EnrollmentPreflight) { value.Schema = "future" },
		func(value *EnrollmentPreflight) { value.TargetRole = "relay" },
		func(value *EnrollmentPreflight) { value.NetworkCIDR = "10.232.0.1/24" },
		func(value *EnrollmentPreflight) { value.LighthouseEndpoints = nil },
		func(value *EnrollmentPreflight) { value.LighthouseEndpoints[1] = value.LighthouseEndpoints[0] },
		func(value *EnrollmentPreflight) { value.LighthouseEndpoints[1] = "lh.example:+4242" },
		func(value *EnrollmentPreflight) { value.TokenExpiresAt = time.Time{} },
	}
	for index, mutate := range tests {
		candidate := valid
		candidate.LighthouseEndpoints = append([]string(nil), valid.LighthouseEndpoints...)
		mutate(&candidate)
		if err := ValidateEnrollmentPreflight(candidate); err == nil {
			t.Fatalf("invalid plan %d was accepted: %#v", index, candidate)
		}
	}
}
