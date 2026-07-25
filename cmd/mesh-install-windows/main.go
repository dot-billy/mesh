//go:build windows

// mesh-install-windows is the minimal privileged Windows installation
// boundary. It is intentionally separate from meshctl, which is installed as
// the long-lived node service executable.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"

	"mesh/internal/buildinfo"
	"mesh/internal/installtrust"
	"mesh/internal/windowsauthenticode"
	"mesh/internal/windowsinstall"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	if err := runContext(ctx, os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "mesh-install-windows:", err)
		os.Exit(1)
	}
}

func runContext(ctx context.Context, args []string, output io.Writer) error {
	if ctx == nil || output == nil || len(args) == 0 {
		return usageError()
	}
	if buildinfo.Identity != buildinfo.DevelopmentIdentity {
		if _, err := authenticateWindowsInstallerSelf(); err != nil {
			return err
		}
	}
	var result windowsinstall.WindowsInstallResult
	var err error
	switch args[0] {
	case "version":
		if len(args) != 1 {
			return usageError()
		}
		return writeVersion(output)
	case "install-online":
		if len(args) != 2 {
			return usageError()
		}
		result, err = windowsinstall.ApplyProductionWindowsOnline(ctx, args[1])
	case "prepare-snapshot":
		if len(args) != 4 {
			return usageError()
		}
		prepared, err := windowsinstall.PrepareProductionWindowsSnapshot(ctx, args[1], args[2], args[3])
		if err != nil {
			return err
		}
		encoder := json.NewEncoder(output)
		encoder.SetEscapeHTML(false)
		return encoder.Encode(prepared)
	case "install":
		if len(args) != 2 {
			return usageError()
		}
		result, err = windowsinstall.ApplyProductionWindowsSnapshot(ctx, args[1])
	case "recover":
		if len(args) != 1 {
			return usageError()
		}
		result, err = windowsinstall.RecoverProductionWindowsInstallation(ctx)
	case "activate":
		if len(args) != 1 {
			return usageError()
		}
		result, err = windowsinstall.ActivateProductionWindowsRuntime(ctx)
	case "uninstall-runtime":
		if len(args) != 1 {
			return usageError()
		}
		uninstalled, err := windowsinstall.UninstallProductionWindowsRuntime(ctx)
		if err != nil {
			return err
		}
		encoder := json.NewEncoder(output)
		encoder.SetEscapeHTML(false)
		return encoder.Encode(uninstalled)
	case "rollback":
		if len(args) != 2 {
			return usageError()
		}
		result, err = windowsinstall.RollbackProductionWindowsInstallation(ctx, args[1])
	default:
		return usageError()
	}
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(result)
}

func usageError() error {
	return errors.New("usage: mesh-install-windows version | install-online EXACT_BUNDLE_URL | prepare-snapshot ABSOLUTE_BUNDLE_JSON ABSOLUTE_WINDOWS_TAR NEW_ABSOLUTE_SNAPSHOT_DIR | install ABSOLUTE_PRIVATE_SNAPSHOT_DIR | recover | activate | uninstall-runtime | rollback PREVIOUS_INSTALLED_ID")
}

func writeVersion(output io.Writer) error {
	info, err := buildinfo.Current()
	if err != nil {
		return err
	}
	bootstrapSHA := ""
	initialRootSHA := ""
	legacyPolicySHA := ""
	authenticodePolicySHA := ""
	if installtrust.Identity != installtrust.DevelopmentPolicy {
		bootstrap, err := installtrust.LoadBootstrap()
		if err != nil {
			return fmt.Errorf("load compiled installer bootstrap: %w", err)
		}
		bootstrapSHA = bootstrap.SHA256
		initialRootSHA = bootstrap.InitialRootSHA256
		legacyPolicySHA = bootstrap.LegacyPolicySHA256
		policy, err := windowsauthenticode.LoadPolicy()
		if err != nil {
			return err
		}
		authenticodePolicySHA = policy.SHA256
	}
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(struct {
		buildinfo.Info
		InstallerTrustBootstrapSHA256   string `json:"installer_trust_bootstrap_sha256"`
		InstallerInitialRootSHA256      string `json:"installer_initial_root_sha256"`
		InstallerLegacyPolicySHA256     string `json:"installer_legacy_policy_sha256"`
		WindowsAuthenticodePolicySHA256 string `json:"windows_authenticode_policy_sha256"`
	}{
		Info: info, InstallerTrustBootstrapSHA256: bootstrapSHA,
		InstallerInitialRootSHA256: initialRootSHA, InstallerLegacyPolicySHA256: legacyPolicySHA,
		WindowsAuthenticodePolicySHA256: authenticodePolicySHA,
	})
}
