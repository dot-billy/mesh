package control

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"
)

const maxRoutedSubnetsPerNode = 8

type reservedIPv4Prefix struct {
	prefix    netip.Prefix
	owner     string
	networkID string
	kind      string
}

func normalizeRoutedSubnets(values []string) ([]string, error) {
	if len(values) > maxRoutedSubnetsPerNode {
		return nil, fmt.Errorf("%w: a node may own at most %d routed subnets", ErrInvalid, maxRoutedSubnetsPerNode)
	}
	if len(values) == 0 {
		return nil, nil
	}
	prefixes := make([]netip.Prefix, len(values))
	seen := make(map[string]struct{}, len(values))
	for index, raw := range values {
		value := strings.TrimSpace(raw)
		prefix, err := parseCanonicalRoutedSubnet(value)
		if err != nil {
			return nil, fmt.Errorf("%w: routed subnet %d: %v", ErrInvalid, index+1, err)
		}
		if _, duplicate := seen[prefix.String()]; duplicate {
			return nil, fmt.Errorf("%w: routed subnet %q is duplicated", ErrInvalid, prefix)
		}
		seen[prefix.String()] = struct{}{}
		prefixes[index] = prefix
	}
	sort.Slice(prefixes, func(i, j int) bool { return compareIPv4Prefixes(prefixes[i], prefixes[j]) < 0 })
	for index := 1; index < len(prefixes); index++ {
		if prefixesOverlap(prefixes[index-1], prefixes[index]) {
			return nil, fmt.Errorf("%w: routed subnets %s and %s overlap", ErrInvalid, prefixes[index-1], prefixes[index])
		}
	}
	result := make([]string, len(prefixes))
	for index, prefix := range prefixes {
		result[index] = prefix.String()
	}
	return result, nil
}

func parseCanonicalRoutedSubnet(value string) (netip.Prefix, error) {
	if value == "" || strings.TrimSpace(value) != value {
		return netip.Prefix{}, errors.New("must be a canonical IPv4 CIDR without surrounding whitespace")
	}
	prefix, err := netip.ParsePrefix(value)
	if err != nil || !prefix.Addr().Is4() || prefix != prefix.Masked() || prefix.String() != value {
		return netip.Prefix{}, errors.New("must be a canonical IPv4 CIDR")
	}
	// Unsafe routes intentionally cover unicast destinations outside the
	// overlay. Reject default, unspecified, loopback, link-local, multicast,
	// and other special-use roots rather than letting a typo hijack host traffic.
	if prefix.Bits() < 1 || !prefix.Addr().IsGlobalUnicast() {
		return netip.Prefix{}, errors.New("must identify a non-default unicast IPv4 range")
	}
	return prefix, nil
}

func validateCanonicalRoutedSubnets(values []string) error {
	normalized, err := normalizeRoutedSubnets(values)
	if err != nil {
		return err
	}
	if len(normalized) != len(values) {
		return errors.New("routed subnets are not canonical")
	}
	for index := range values {
		if values[index] != normalized[index] {
			return errors.New("routed subnets are not canonical and deterministically ordered")
		}
	}
	return nil
}

func validateNewRoutedSubnets(state State, subnets []string) error {
	if len(subnets) == 0 {
		return nil
	}
	reservations, err := activeReservedIPv4Prefixes(state)
	if err != nil {
		return err
	}
	for _, value := range subnets {
		prefix, _ := netip.ParsePrefix(value)
		for _, reservation := range reservations {
			if prefixesOverlap(prefix, reservation.prefix) {
				return fmt.Errorf("%w: routed subnet %s overlaps %s %s owned by %s", ErrConflict, prefix, reservation.kind, reservation.prefix, reservation.owner)
			}
		}
	}
	return nil
}

func validateRoutedSubnetsForNode(state State, nodeID string, subnets []string) error {
	node, nodeOK := findNode(state, nodeID)
	if !nodeOK {
		return ErrNotFound
	}
	reservations, err := activeReservedIPv4Prefixes(state)
	if err != nil {
		return err
	}
	for _, value := range subnets {
		prefix, _ := netip.ParsePrefix(value)
		for _, reservation := range reservations {
			if reservation.kind == "routed subnet" && reservation.owner == nodeID {
				continue
			}
			if reservation.kind == "routed subnet" && reservation.networkID == node.NetworkID && prefix == reservation.prefix {
				owner, ok := findNode(state, reservation.owner)
				if ok && owner.Status == "active" && owner.EnrolledAt != nil {
					continue
				}
			}
			if prefixesOverlap(prefix, reservation.prefix) {
				return fmt.Errorf("%w: routed subnet %s overlaps %s %s owned by %s", ErrConflict, prefix, reservation.kind, reservation.prefix, reservation.owner)
			}
		}
	}
	return nil
}

func managedCIDROverlapsRoutedSubnet(state State, cidr string) (string, bool) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return "", false
	}
	for _, node := range state.Nodes {
		if node.Status == "revoked" {
			continue
		}
		for _, value := range node.RoutedSubnets {
			routed, parseErr := netip.ParsePrefix(value)
			if parseErr == nil && prefixesOverlap(prefix, routed) {
				return value, true
			}
		}
	}
	for _, network := range state.Networks {
		if !routeProfileEditActive(network.RouteProfileEdit) {
			continue
		}
		for _, value := range routeProfileEditAdditions(network.RouteProfileEdit) {
			routed, parseErr := netip.ParsePrefix(value)
			if parseErr == nil && prefixesOverlap(prefix, routed) {
				return value, true
			}
		}
	}
	return "", false
}

func activeReservedIPv4Prefixes(state State) ([]reservedIPv4Prefix, error) {
	reservations := make([]reservedIPv4Prefix, 0, len(state.Networks)+len(state.Nodes))
	for _, network := range state.Networks {
		prefix, err := netip.ParsePrefix(network.CIDR)
		if err != nil {
			return nil, fmt.Errorf("network %s has an invalid CIDR", network.ID)
		}
		reservations = append(reservations, reservedIPv4Prefix{prefix: prefix, owner: network.ID, networkID: network.ID, kind: "managed network"})
	}
	for _, node := range state.Nodes {
		if node.Status == "revoked" {
			continue
		}
		for _, value := range node.RoutedSubnets {
			prefix, err := netip.ParsePrefix(value)
			if err != nil {
				return nil, fmt.Errorf("node %s has an invalid routed subnet", node.ID)
			}
			reservations = append(reservations, reservedIPv4Prefix{prefix: prefix, owner: node.ID, networkID: node.NetworkID, kind: "routed subnet"})
		}
	}
	for _, network := range state.Networks {
		edit := network.RouteProfileEdit
		if !routeProfileEditActive(edit) {
			continue
		}
		owner, ok := findNode(state, edit.NodeID)
		if !ok {
			return nil, fmt.Errorf("network %s has a route-profile edit for a missing node", network.ID)
		}
		for _, value := range routeProfileEditAdditions(edit) {
			if slices.Contains(owner.RoutedSubnets, value) {
				continue
			}
			prefix, err := netip.ParsePrefix(value)
			if err != nil {
				return nil, fmt.Errorf("network %s has an invalid staged routed subnet", network.ID)
			}
			reservations = append(reservations, reservedIPv4Prefix{prefix: prefix, owner: owner.ID, networkID: owner.NetworkID, kind: "routed subnet"})
		}
	}
	return reservations, nil
}

func validateReservedIPv4PrefixGraph(state State) error {
	reservations, err := activeReservedIPv4Prefixes(state)
	if err != nil {
		return err
	}
	sort.Slice(reservations, func(i, j int) bool {
		comparison := compareIPv4Prefixes(reservations[i].prefix, reservations[j].prefix)
		if comparison != 0 {
			return comparison < 0
		}
		if reservations[i].kind != reservations[j].kind {
			return reservations[i].kind < reservations[j].kind
		}
		return reservations[i].owner < reservations[j].owner
	})
	for index := 1; index < len(reservations); index++ {
		previous, current := reservations[index-1], reservations[index]
		if prefixesOverlap(previous.prefix, current.prefix) {
			if previous.kind == "routed subnet" && current.kind == "routed subnet" &&
				previous.networkID == current.networkID && previous.prefix == current.prefix {
				owners := 1
				for scan := index; scan < len(reservations) && reservations[scan].kind == "routed subnet" && reservations[scan].networkID == current.networkID && reservations[scan].prefix == current.prefix; scan++ {
					owners++
				}
				if owners > maxRoutePolicyGateways {
					return fmt.Errorf("routed subnet %s has more than %d gateways", current.prefix, maxRoutePolicyGateways)
				}
				continue
			}
			return fmt.Errorf("%s %s owned by %s overlaps %s %s owned by %s", previous.kind, previous.prefix, previous.owner, current.kind, current.prefix, current.owner)
		}
	}
	return nil
}

func prefixesOverlap(left, right netip.Prefix) bool {
	return left.Contains(right.Addr()) || right.Contains(left.Addr())
}

func compareIPv4Prefixes(left, right netip.Prefix) int {
	leftBytes, rightBytes := left.Addr().As4(), right.Addr().As4()
	for index := range leftBytes {
		if leftBytes[index] < rightBytes[index] {
			return -1
		}
		if leftBytes[index] > rightBytes[index] {
			return 1
		}
	}
	if left.Bits() < right.Bits() {
		return -1
	}
	if left.Bits() > right.Bits() {
		return 1
	}
	return 0
}
