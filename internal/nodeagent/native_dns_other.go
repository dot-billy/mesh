//go:build !linux && !windows

package nodeagent

import "context"

type unsupportedNativeDNSManager struct{}

func NewNativeDNSManager(CommandRunner) NativeDNSReconciler { return unsupportedNativeDNSManager{} }

func (unsupportedNativeDNSManager) Reconcile(_ context.Context, signedConfig string) error {
	_, enabled, err := parseNativeDNSConfig(signedConfig)
	if err != nil {
		return err
	}
	if enabled {
		return ErrNativeDNSUnsupported
	}
	return nil
}

func (unsupportedNativeDNSManager) Disable(context.Context) error { return nil }
