//go:build !linux

package nodeagent

import (
	"context"
	"net/netip"
)

func inspectPreEnrollmentRoutes(context.Context, netip.Prefix) (supported, overlap bool, err error) {
	return false, false, nil
}
