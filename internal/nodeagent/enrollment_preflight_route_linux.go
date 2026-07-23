//go:build linux

package nodeagent

import (
	"context"
	"errors"
	"net/netip"
)

func inspectPreEnrollmentRoutes(ctx context.Context, network netip.Prefix) (supported, overlap bool, err error) {
	if ctx == nil || ctx.Err() != nil {
		return true, false, errors.New("pre-enrollment route context is unavailable")
	}
	routes, err := loadIPv4RouteInventory()
	if err != nil || ctx.Err() != nil {
		return true, false, errors.New("pre-enrollment IPv4 route inventory is unavailable")
	}
	overlap, complete := preEnrollmentRouteInventoryOverlaps(network, routes)
	if !complete {
		return true, false, errors.New("pre-enrollment IPv4 route inventory is invalid")
	}
	return true, overlap, nil
}
