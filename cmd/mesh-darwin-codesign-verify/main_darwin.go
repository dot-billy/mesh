//go:build darwin

// mesh-darwin-codesign-verify is a narrow native verifier for the signed
// package bootstrap and three final executables in one Mesh Darwin bundle. It
// does not sign, package, install, download, or mutate launchd. The protected
// workflow must independently bind this verifier's own production bytes.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"time"

	"mesh/internal/darwincodesign"
)

const usage = "usage: mesh-darwin-codesign-verify --arch <amd64|arm64> --mesh-install <signed-mesh-install> --meshctl <signed-meshctl> --nebula <signed-nebula> --nebula-cert <signed-nebula-cert>"

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "mesh-darwin-codesign-verify:", err)
		os.Exit(1)
	}
}

func run(args []string, output, diagnostics io.Writer) error {
	if output == nil || diagnostics == nil {
		return errors.New("Darwin code-signature verifier output streams are required")
	}
	flags := flag.NewFlagSet("mesh-darwin-codesign-verify", flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	flags.Usage = func() { fmt.Fprintln(diagnostics, usage) }
	arch := flags.String("arch", "", "exact native Darwin architecture")
	meshInstall := flags.String("mesh-install", "", "final Developer ID signed mesh-install")
	meshctl := flags.String("meshctl", "", "final Developer ID signed meshctl")
	nebula := flags.String("nebula", "", "final Developer ID signed nebula")
	nebulaCert := flags.String("nebula-cert", "", "final Developer ID signed nebula-cert")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("positional arguments are not accepted")
	}
	if *arch != runtime.GOARCH || (*arch != "amd64" && *arch != "arm64") {
		return errors.New("--arch must exactly match this native Darwin host")
	}
	for name, value := range map[string]string{
		"--mesh-install": *meshInstall, "--meshctl": *meshctl,
		"--nebula": *nebula, "--nebula-cert": *nebulaCert,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s is required", name)
		}
	}
	receipt, err := darwincodesign.CreateReceipt(*arch, map[string]string{
		"mesh-install": *meshInstall, "bin/meshctl": *meshctl,
		"bin/nebula": *nebula, "bin/nebula-cert": *nebulaCert,
	}, time.Now().UTC().Truncate(time.Second))
	if err != nil {
		return err
	}
	raw, err := darwincodesign.EncodeReceipt(receipt)
	if err != nil {
		return err
	}
	if _, err := output.Write(raw); err != nil {
		return fmt.Errorf("write Darwin code-signing receipt: %w", err)
	}
	return nil
}
