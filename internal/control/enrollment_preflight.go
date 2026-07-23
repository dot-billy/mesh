package control

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
)

const (
	EnrollmentPreflightSchemaV1       = "mesh-enrollment-preflight-v1"
	maxEnrollmentPreflightLighthouses = 64
)

// EnrollmentPreflight is the minimum token-scoped topology needed to check a
// future node's local routes and resolver before enrollment consumes its
// one-time credential. It deliberately contains no CA, node address, groups,
// certificate material, or private control-plane state.
type EnrollmentPreflight struct {
	Schema              string    `json:"schema"`
	TargetRole          string    `json:"target_role"`
	NetworkCIDR         string    `json:"network_cidr"`
	LighthouseEndpoints []string  `json:"lighthouse_endpoints"`
	TokenExpiresAt      time.Time `json:"token_expires_at"`
}

// ValidateEnrollmentPreflight rejects partial, noncanonical, or unbounded
// plans before a client uses them to make a local enrollment decision.
func ValidateEnrollmentPreflight(plan EnrollmentPreflight) error {
	if plan.Schema != EnrollmentPreflightSchemaV1 {
		return fmt.Errorf("%w: enrollment preflight schema is invalid", ErrInvalid)
	}
	if plan.TargetRole != "member" && plan.TargetRole != "lighthouse" {
		return fmt.Errorf("%w: enrollment preflight target role is invalid", ErrInvalid)
	}
	ip, network, err := net.ParseCIDR(plan.NetworkCIDR)
	ones, bits := 0, 0
	if err == nil {
		ones, bits = network.Mask.Size()
	}
	if err != nil || ip.To4() == nil || network.String() != plan.NetworkCIDR || bits != 32 || ones < 16 || ones > 28 {
		return fmt.Errorf("%w: enrollment preflight network is invalid", ErrInvalid)
	}
	if plan.LighthouseEndpoints == nil || len(plan.LighthouseEndpoints) > maxEnrollmentPreflightLighthouses {
		return fmt.Errorf("%w: enrollment preflight lighthouse set is invalid", ErrInvalid)
	}
	previous := ""
	for _, endpoint := range plan.LighthouseEndpoints {
		if endpoint == "" || endpoint <= previous {
			return fmt.Errorf("%w: enrollment preflight lighthouse endpoints are not uniquely ordered", ErrInvalid)
		}
		if err := validateEndpoint(endpoint); err != nil {
			return fmt.Errorf("%w: enrollment preflight lighthouse endpoint is invalid", ErrInvalid)
		}
		previous = endpoint
	}
	if plan.TokenExpiresAt.IsZero() || plan.TokenExpiresAt.Location() != time.UTC {
		return fmt.Errorf("%w: enrollment preflight expiry is invalid", ErrInvalid)
	}
	return nil
}

// PreflightEnrollment authorizes a read-only point-in-time plan with an
// unused, unexpired enrollment credential. Used tokens and nodes that are no
// longer pending fail identically to unknown tokens. The target lighthouse is
// included because its successful enrollment would immediately place its
// public endpoint in the signed static host map.
func (s *Service) PreflightEnrollment(token string) (EnrollmentPreflight, error) {
	token = strings.TrimSpace(token)
	if !ValidBearerToken(token) {
		return EnrollmentPreflight{}, ErrUnauthorized
	}
	now := s.now().UTC()
	tokenHash := HashToken(token)
	var result EnrollmentPreflight
	err := s.readCurrentState(func(state State) error {
		var enrollment EnrollmentToken
		found := false
		for _, candidate := range state.Enrollments {
			if candidate.UsedAt == nil && now.Before(candidate.ExpiresAt) && TokenHashEqual(candidate.TokenHash, tokenHash) {
				enrollment = candidate
				found = true
				break
			}
		}
		if !found {
			return ErrUnauthorized
		}
		node, ok := findNode(state, enrollment.NodeID)
		if !ok || node.Status != "pending" || node.EnrolledAt != nil {
			return ErrUnauthorized
		}
		network, ok := findNetwork(state, node.NetworkID)
		if !ok {
			return ErrUnauthorized
		}

		endpoints := make(map[string]struct{})
		for _, candidate := range state.Nodes {
			if candidate.NetworkID == network.ID && candidate.Role == "lighthouse" &&
				candidate.Status == "active" && candidate.PublicEndpoint != "" {
				endpoints[candidate.PublicEndpoint] = struct{}{}
			}
		}
		if node.Role == "lighthouse" && node.PublicEndpoint != "" {
			endpoints[node.PublicEndpoint] = struct{}{}
		}
		if len(endpoints) > maxEnrollmentPreflightLighthouses {
			return fmt.Errorf("%w: enrollment preflight exceeds the lighthouse limit", ErrConflict)
		}
		ordered := make([]string, 0, len(endpoints))
		for endpoint := range endpoints {
			ordered = append(ordered, endpoint)
		}
		sort.Strings(ordered)
		result = EnrollmentPreflight{
			Schema: EnrollmentPreflightSchemaV1, TargetRole: node.Role,
			NetworkCIDR: network.CIDR, LighthouseEndpoints: ordered,
			TokenExpiresAt: enrollment.ExpiresAt.UTC(),
		}
		return ValidateEnrollmentPreflight(result)
	})
	if err != nil {
		return EnrollmentPreflight{}, err
	}
	return result, nil
}
