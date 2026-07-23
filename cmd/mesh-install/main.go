// mesh-install is the minimal, release-rooted Linux installation boundary.
// Keeping it separate from meshctl prevents privileged package operations from
// inheriting the control-plane and node-lifecycle command surface.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"mesh/internal/buildinfo"
	"mesh/internal/installtrust"
	"mesh/internal/linuxinstall"
)

var applyOnline = linuxinstall.ApplyOnline

func main() {
	syscall.Umask(0o077)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := runContext(ctx, os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "mesh-install:", err)
		os.Exit(1)
	}
}

func run(args []string, output io.Writer) error {
	return runContext(context.Background(), args, output)
}

func runContext(ctx context.Context, args []string, output io.Writer) error {
	if len(args) == 0 {
		return usageError()
	}
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
		result, err := applyOnline(ctx, args[1])
		if err != nil {
			return err
		}
		return writeInstallResult(output, result)
	case "install":
		if len(args) != 2 {
			return usageError()
		}
		result, err := linuxinstall.ApplySnapshot(ctx, args[1])
		if err != nil {
			return err
		}
		return writeInstallResult(output, result)
	case "recover":
		if len(args) != 1 {
			return usageError()
		}
		result, err := linuxinstall.RecoverInstallation(ctx)
		if err != nil {
			return err
		}
		return writeInstallResult(output, result)
	case "activate":
		if len(args) != 1 {
			return usageError()
		}
		result, err := linuxinstall.ActivateInstallation(ctx)
		if err != nil {
			return err
		}
		return writeInstallResult(output, result)
	case "rollback":
		if len(args) != 2 {
			return usageError()
		}
		result, err := linuxinstall.RollbackInstallation(ctx, args[1])
		if err != nil {
			return err
		}
		return writeInstallResult(output, result)
	default:
		return usageError()
	}
}

func usageError() error {
	return fmt.Errorf("usage: mesh-install version | install-online EXACT_BUNDLE_URL | install ABSOLUTE_SNAPSHOT_DIR | recover | activate | rollback INSTALLED_ID")
}

func writeVersion(output io.Writer) error {
	info, err := buildinfo.Current()
	if err != nil {
		return err
	}
	bootstrapSHA := ""
	initialRootSHA := ""
	legacyPolicySHA := ""
	if installtrust.Identity != installtrust.DevelopmentPolicy {
		bootstrap, err := installtrust.LoadBootstrap()
		if err != nil {
			return fmt.Errorf("load compiled installer bootstrap: %w", err)
		}
		bootstrapSHA = bootstrap.SHA256
		initialRootSHA = bootstrap.InitialRootSHA256
		legacyPolicySHA = bootstrap.LegacyPolicySHA256
	}
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(struct {
		buildinfo.Info
		InstallerTrustBootstrapSHA256 string `json:"installer_trust_bootstrap_sha256"`
		InstallerInitialRootSHA256    string `json:"installer_initial_root_sha256"`
		InstallerLegacyPolicySHA256   string `json:"installer_legacy_policy_sha256"`
	}{
		Info: info, InstallerTrustBootstrapSHA256: bootstrapSHA,
		InstallerInitialRootSHA256: initialRootSHA, InstallerLegacyPolicySHA256: legacyPolicySHA,
	})
}

func writeInstallResult(output io.Writer, result linuxinstall.InstallResult) error {
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(result)
}
