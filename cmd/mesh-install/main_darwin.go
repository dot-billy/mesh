//go:build darwin

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"

	"mesh/internal/darwincodesign"
	"mesh/internal/darwininstall"
	"mesh/internal/darwinnodepackage"
)

var (
	applyDarwinOnline            = darwininstall.ApplyProductionDarwinOnline
	applyDarwinSnapshot          = darwininstall.ApplyProductionDarwinSnapshot
	applyDarwinPackageSnapshot   = darwininstall.ApplyProductionDarwinPackageSnapshot
	recoverDarwin                = darwininstall.RecoverProductionDarwinInstallation
	activateDarwin               = darwininstall.ActivateProductionDarwinRuntime
	uninstallDarwin              = darwininstall.UninstallProductionDarwinRuntime
	rollbackDarwin               = darwininstall.RollbackProductionDarwinInstallation
	loadDarwinNodePackagePolicy  = darwinnodepackage.LoadPolicy
	verifyDarwinPackageBootstrap = darwincodesign.VerifyFile
)

func platformUsage() string {
	return "mesh-install version | install-online EXACT_BUNDLE_URL | install ABSOLUTE_SNAPSHOT_DIR | recover | activate | uninstall-runtime | rollback INSTALLED_ID"
}

func platformCodeSigningPolicySHA256() (string, error) {
	if darwincodesign.Identity == darwincodesign.DevelopmentPolicy {
		return "", nil
	}
	policy, err := darwincodesign.LoadPolicy()
	if err != nil {
		return "", err
	}
	return policy.SHA256, nil
}

func platformNodePackagePolicySHA256() (string, error) {
	if darwinnodepackage.Identity == darwinnodepackage.DevelopmentPolicy {
		return "", nil
	}
	policy, err := darwinnodepackage.LoadPolicy()
	if err != nil {
		return "", err
	}
	return policy.SHA256, nil
}

func runPlatformPackagePostinstallContext(ctx context.Context, args []string, output io.Writer) error {
	if ctx == nil || output == nil {
		return errors.New("Darwin package post-install requires a context and output")
	}
	if len(args) != 4 || !path.IsAbs(args[0]) || path.Clean(args[0]) != args[0] ||
		!strings.HasSuffix(args[0], ".pkg") || args[2] != "/" || args[3] != "/" {
		return errors.New("Darwin package post-install invocation is invalid")
	}
	policy, err := loadDarwinNodePackagePolicy()
	if err != nil {
		return err
	}
	if args[1] != policy.PackageInstallLocation {
		return errors.New("Darwin package post-install location differs from compiled policy")
	}
	verification, err := verifyDarwinPackageBootstrap(
		policy.InstalledBootstrapPath,
		darwincodesign.MeshInstallRole,
	)
	if err != nil {
		return fmt.Errorf("authenticate installed Darwin package bootstrap: %w", err)
	}
	if verification.Role != darwincodesign.MeshInstallRole ||
		verification.Identifier == "" || verification.TeamID == "" ||
		verification.PolicySHA256 == "" {
		return errors.New("installed Darwin package bootstrap returned incomplete code-signing evidence")
	}
	result, err := applyDarwinPackageSnapshot(ctx, policy.PackageSnapshotPath)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(result)
}

func runPlatformContext(ctx context.Context, args []string, output io.Writer) error {
	var result darwininstall.DarwinInstallResult
	var err error
	switch args[0] {
	case "install-online":
		if len(args) != 2 {
			return usageError()
		}
		result, err = applyDarwinOnline(ctx, args[1])
	case "install":
		if len(args) != 2 {
			return usageError()
		}
		result, err = applyDarwinSnapshot(ctx, args[1])
	case "recover":
		if len(args) != 1 {
			return usageError()
		}
		result, err = recoverDarwin(ctx)
	case "activate":
		if len(args) != 1 {
			return usageError()
		}
		result, err = activateDarwin(ctx)
	case "uninstall-runtime":
		if len(args) != 1 {
			return usageError()
		}
		uninstalled, err := uninstallDarwin(ctx)
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
		result, err = rollbackDarwin(ctx, args[1])
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
