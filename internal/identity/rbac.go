package identity

import (
	"errors"
	"slices"
)

// Role is the coarse-grained operator role attached to an authenticated
// principal. Permissions are derived server-side; clients receive them only
// as presentation hints and must never be trusted for authorization.
type Role string

const (
	RoleMember   Role = "member"
	RoleViewer   Role = "viewer"
	RoleOperator Role = "operator"
	RoleAdmin    Role = "admin"
)

type Permission string

const (
	PermissionNetworksRead     Permission = "networks.read"
	PermissionNetworksWrite    Permission = "networks.write"
	PermissionNetworksSecurity Permission = "networks.security"
	PermissionNodesEnrollSelf  Permission = "nodes.enroll.self"
	PermissionIdentityManage   Permission = "identity.manage"
	PermissionAuditRead        Permission = "audit.read"
)

var rolePermissions = map[Role][]Permission{
	RoleMember: {
		PermissionNetworksRead,
		PermissionNodesEnrollSelf,
	},
	RoleViewer: {
		PermissionNetworksRead,
		PermissionAuditRead,
	},
	RoleOperator: {
		PermissionNetworksRead,
		PermissionNetworksWrite,
		PermissionNodesEnrollSelf,
		PermissionAuditRead,
	},
	RoleAdmin: {
		PermissionNetworksRead,
		PermissionNetworksWrite,
		PermissionNetworksSecurity,
		PermissionNodesEnrollSelf,
		PermissionIdentityManage,
		PermissionAuditRead,
	},
}

type RoleBinding struct {
	Role     Role          `json:"role"`
	Selector AdminSelector `json:"selector"`
}

func (r Role) Validate() error {
	if _, ok := rolePermissions[r]; !ok {
		return errors.New("unsupported RBAC role")
	}
	return nil
}

func PermissionsForRole(role Role) ([]Permission, error) {
	permissions, ok := rolePermissions[role]
	if !ok {
		return nil, errors.New("unsupported RBAC role")
	}
	return append([]Permission(nil), permissions...), nil
}

func RoleAllows(role Role, permission Permission) bool {
	permissions, ok := rolePermissions[role]
	return ok && slices.Contains(permissions, permission)
}

// RoleForPrincipal resolves a principal against the normalized identity
// policy. Legacy, service, and break-glass principals retain administrator
// authority; existing OIDC admin selectors remain administrator bindings.
func RoleForPrincipal(principal Principal, config IdentityConfig) (Role, error) {
	if err := principal.Validate(); err != nil {
		return "", err
	}
	switch principal.Kind {
	case PrincipalLegacyAdmin, PrincipalService, PrincipalBreakGlass:
		return RoleAdmin, nil
	case PrincipalOIDCAdmin:
		if config.OIDC == nil {
			return "", ErrUnauthorized
		}
		for _, selector := range config.OIDC.Admins {
			if selectorMatchesPrincipal(selector, principal) {
				return RoleAdmin, nil
			}
		}
		role := Role("")
		for _, binding := range config.OIDC.RoleBindings {
			if selectorMatchesPrincipal(binding.Selector, principal) && roleRank(binding.Role) > roleRank(role) {
				role = binding.Role
			}
		}
		if role == "" {
			return "", ErrUnauthorized
		}
		return role, nil
	default:
		return "", ErrUnauthorized
	}
}

func selectorMatchesPrincipal(selector AdminSelector, principal Principal) bool {
	switch selector.Kind {
	case "subject":
		return principal.Subject == selector.Value
	case "verified_email":
		// OIDC validation only persists an email after the signed
		// email_verified claim was proven true for selector authorization.
		return principal.Email == selector.Value
	case "group":
		return slices.Contains(principal.Groups, selector.Value)
	default:
		return false
	}
}

func roleRank(role Role) int {
	switch role {
	case RoleMember:
		return 1
	case RoleViewer:
		return 2
	case RoleOperator:
		return 3
	case RoleAdmin:
		return 4
	default:
		return 0
	}
}
