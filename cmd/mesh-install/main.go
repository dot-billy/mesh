//go:build linux || darwin

// mesh-install is the minimal, release-rooted native installation boundary for
// Linux and macOS. Keeping it separate from meshctl prevents privileged package
// operations from inheriting the control-plane and node-lifecycle command
// surface.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"mesh/internal/buildinfo"
	"mesh/internal/installtrust"
)

func main() {
	syscall.Umask(0o077)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	var err error
	if filepath.Base(os.Args[0]) == "postinstall" {
		err = runPlatformPackagePostinstallContext(ctx, os.Args[1:], os.Stdout)
	} else {
		err = runContext(ctx, os.Args[1:], os.Stdout)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "mesh-install:", err)
		os.Exit(1)
	}
}

func run(args []string, output io.Writer) error {
	return runContext(context.Background(), args, output)
}

func runContext(ctx context.Context, args []string, output io.Writer) error {
	if ctx == nil || output == nil || len(args) == 0 {
		return usageError()
	}
	if args[0] == "version" {
		if len(args) == 1 {
			return writeVersion(output)
		}
		return usageError()
	}
	return runPlatformContext(ctx, args, output)
}

func usageError() error {
	return fmt.Errorf("usage: %s", platformUsage())
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
	darwinCodesignPolicySHA, err := platformCodeSigningPolicySHA256()
	if err != nil {
		return err
	}
	darwinNodePackagePolicySHA, err := platformNodePackagePolicySHA256()
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(struct {
		buildinfo.Info
		InstallerTrustBootstrapSHA256 string `json:"installer_trust_bootstrap_sha256"`
		InstallerInitialRootSHA256    string `json:"installer_initial_root_sha256"`
		InstallerLegacyPolicySHA256   string `json:"installer_legacy_policy_sha256"`
		DarwinCodeSigningPolicySHA256 string `json:"darwin_code_signing_policy_sha256"`
		DarwinNodePackagePolicySHA256 string `json:"darwin_node_package_policy_sha256"`
	}{
		Info: info, InstallerTrustBootstrapSHA256: bootstrapSHA,
		InstallerInitialRootSHA256: initialRootSHA, InstallerLegacyPolicySHA256: legacyPolicySHA,
		DarwinCodeSigningPolicySHA256: darwinCodesignPolicySHA,
		DarwinNodePackagePolicySHA256: darwinNodePackagePolicySHA,
	})
}
