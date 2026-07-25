//go:build windows

// mesh-authenticode-verify is a narrow native Windows verifier for the four
// final PEs in one signed Mesh bundle. It does not sign, package, install,
// download, or mutate services and resolver state.
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

	"mesh/internal/windowsauthenticode"
)

const usage = "usage: mesh-authenticode-verify --arch <amd64|arm64> --meshctl <meshctl.exe> --nebula <nebula.exe> --nebula-cert <nebula-cert.exe> --wintun <wintun.dll>"

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "mesh-authenticode-verify:", err)
		os.Exit(1)
	}
}

func run(args []string, output, diagnostics io.Writer) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	if _, err := windowsauthenticode.VerifyFile(self, windowsauthenticode.MeshSignerRole); err != nil {
		return fmt.Errorf("authenticate native Authenticode verifier: %w", err)
	}
	flags := flag.NewFlagSet("mesh-authenticode-verify", flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	flags.Usage = func() { fmt.Fprintln(diagnostics, usage) }
	arch := flags.String("arch", "", "exact Windows architecture")
	meshctl := flags.String("meshctl", "", "final signed meshctl.exe")
	nebula := flags.String("nebula", "", "final signed nebula.exe")
	nebulaCert := flags.String("nebula-cert", "", "final signed nebula-cert.exe")
	wintun := flags.String("wintun", "", "final signed wintun.dll")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("positional arguments are not accepted")
	}
	if *arch != runtime.GOARCH || (*arch != "amd64" && *arch != "arm64") {
		return errors.New("--arch must exactly match this native Windows host")
	}
	for name, value := range map[string]string{"--meshctl": *meshctl, "--nebula": *nebula, "--nebula-cert": *nebulaCert, "--wintun": *wintun} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s is required", name)
		}
	}
	paths := map[string]string{
		"bin/dist/windows/wintun/bin/" + *arch + "/wintun.dll": *wintun,
		"bin/meshctl.exe": *meshctl, "bin/nebula-cert.exe": *nebulaCert,
		"bin/nebula.exe": *nebula,
	}
	receipt, err := windowsauthenticode.CreateReceipt(*arch, paths, time.Now().UTC().Truncate(time.Second))
	if err != nil {
		return err
	}
	raw, err := windowsauthenticode.EncodeReceipt(receipt)
	if err != nil {
		return err
	}
	if _, err := output.Write(raw); err != nil {
		return fmt.Errorf("write Windows Authenticode receipt: %w", err)
	}
	return nil
}
