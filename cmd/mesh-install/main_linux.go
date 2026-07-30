//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"

	"mesh/internal/linuxinstall"
)

var applyOnline = linuxinstall.ApplyOnline

func platformUsage() string {
	return "mesh-install version | install-online EXACT_BUNDLE_URL | install ABSOLUTE_SNAPSHOT_DIR | recover | activate | rollback INSTALLED_ID"
}

func platformCodeSigningPolicySHA256() (string, error) {
	return "", nil
}

func platformNodePackagePolicySHA256() (string, error) {
	return "", nil
}

func runPlatformPackagePostinstallContext(context.Context, []string, io.Writer) error {
	return errors.New("Darwin package post-install is unavailable on Linux")
}

func runPlatformContext(ctx context.Context, args []string, output io.Writer) error {
	var result linuxinstall.InstallResult
	var err error
	switch args[0] {
	case "install-online":
		if len(args) != 2 {
			return usageError()
		}
		result, err = applyOnline(ctx, args[1])
	case "install":
		if len(args) != 2 {
			return usageError()
		}
		result, err = linuxinstall.ApplySnapshot(ctx, args[1])
	case "recover":
		if len(args) != 1 {
			return usageError()
		}
		result, err = linuxinstall.RecoverInstallation(ctx)
	case "activate":
		if len(args) != 1 {
			return usageError()
		}
		result, err = linuxinstall.ActivateInstallation(ctx)
	case "rollback":
		if len(args) != 2 {
			return usageError()
		}
		result, err = linuxinstall.RollbackInstallation(ctx, args[1])
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
