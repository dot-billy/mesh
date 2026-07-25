package nodeagent

import (
	"context"
	"errors"

	"mesh/internal/control"
)

var ErrNativeDNSUnsupported = errors.New("native DNS integration is unsupported on this platform")

// NativeDNSReconciler owns only transient host resolver state. The desired
// policy is extracted from exact signed Nebula configuration on every cycle.
type NativeDNSReconciler interface {
	Reconcile(context.Context, string) error
	Disable(context.Context) error
}

func parseNativeDNSConfig(config string) (control.NativeDNSPolicy, bool, error) {
	return control.ParseNativeDNSPolicy(config)
}
