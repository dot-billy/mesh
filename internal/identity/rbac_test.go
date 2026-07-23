package identity

import (
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestRoleForPrincipalResolvesBindingsAndLegacyAuthority(t *testing.T) {
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	config := IdentityConfig{OIDC: &OIDCConfig{
		Admins: []AdminSelector{{Kind: "group", Value: "mesh-admins"}},
		RoleBindings: []RoleBinding{
			{Role: RoleViewer, Selector: AdminSelector{Kind: "group", Value: "mesh-viewers"}},
			{Role: RoleOperator, Selector: AdminSelector{Kind: "group", Value: "mesh-operators"}},
		},
	}}

	tests := []struct {
		name   string
		groups []string
		want   Role
	}{
		{name: "viewer", groups: []string{"mesh-viewers"}, want: RoleViewer},
		{name: "operator", groups: []string{"mesh-operators"}, want: RoleOperator},
		{name: "highest matching role", groups: []string{"mesh-operators", "mesh-viewers"}, want: RoleOperator},
		{name: "legacy admin selector", groups: []string{"mesh-admins"}, want: RoleAdmin},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			principal, err := NewOIDCPrincipal("https://id.example.test/tenant", "subject-"+test.name, "User", "", test.groups, "mfa", []string{"otp"}, now)
			if err != nil {
				t.Fatal(err)
			}
			role, err := RoleForPrincipal(principal, config)
			if err != nil || role != test.want {
				t.Fatalf("role=%q error=%v, want %q", role, err, test.want)
			}
		})
	}

	unmatched, err := NewOIDCPrincipal("https://id.example.test/tenant", "unmatched", "User", "", []string{"other"}, "mfa", []string{"otp"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := RoleForPrincipal(unmatched, config); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("unmatched principal error=%v, want unauthorized", err)
	}
	legacy, err := NewLegacyPrincipal(now)
	if err != nil {
		t.Fatal(err)
	}
	if role, err := RoleForPrincipal(legacy, IdentityConfig{}); err != nil || role != RoleAdmin {
		t.Fatalf("legacy role=%q error=%v", role, err)
	}
}

func TestRolePermissionMatrixIsExplicitAndDefensivelyCopied(t *testing.T) {
	want := map[Role][]Permission{
		RoleViewer:   {PermissionNetworksRead, PermissionAuditRead},
		RoleOperator: {PermissionNetworksRead, PermissionNetworksWrite, PermissionAuditRead},
		RoleAdmin:    {PermissionNetworksRead, PermissionNetworksWrite, PermissionNetworksSecurity, PermissionIdentityManage, PermissionAuditRead},
	}
	for role, expected := range want {
		permissions, err := PermissionsForRole(role)
		if err != nil || !reflect.DeepEqual(permissions, expected) {
			t.Fatalf("permissions for %q=%v error=%v, want %v", role, permissions, err, expected)
		}
		permissions[0] = "mutated"
		fresh, _ := PermissionsForRole(role)
		if fresh[0] == "mutated" {
			t.Fatalf("permissions for %q shared mutable state", role)
		}
	}
	if RoleAllows(RoleViewer, PermissionNetworksWrite) || RoleAllows(RoleOperator, PermissionNetworksSecurity) || !RoleAllows(RoleAdmin, PermissionIdentityManage) {
		t.Fatal("role permission boundaries are incorrect")
	}
}
