// mesh-deps performs narrowly scoped, lock-driven dependency intake. It does
// not install software, mutate services, or accept network trust overrides.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"

	"mesh/internal/nebulaartifact"
	"mesh/internal/nebulaobserverartifact"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "mesh-deps:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, output io.Writer) error {
	if len(args) == 0 {
		return usageError()
	}
	switch args[0] {
	case "fetch-nebula":
		return runFetchNebula(ctx, args[1:], output)
	case "build-nebula-observer":
		return runBuildNebulaObserver(ctx, args[1:], output)
	case "build-nebula-windows-runtime":
		return runBuildNebulaWindowsRuntime(ctx, args[1:], output)
	case "build-nebula-darwin-runtime":
		return runBuildNebulaDarwinRuntime(ctx, args[1:], output)
	default:
		return usageError()
	}
}

func runBuildNebulaDarwinRuntime(ctx context.Context, args []string, output io.Writer) error {
	flags := flag.NewFlagSet("build-nebula-darwin-runtime", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	arch := flags.String("arch", "", "locked Darwin target architecture")
	outputDir := flags.String("output-dir", "", "new directory for verified files")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("build-nebula-darwin-runtime does not accept positional arguments")
	}
	if strings.TrimSpace(*arch) == "" || strings.TrimSpace(*outputDir) == "" {
		return errors.New("--arch and --output-dir are required")
	}
	result, err := nebulaobserverartifact.BuildDarwin(ctx, *arch, *outputDir)
	if err != nil {
		return err
	}
	fmt.Fprintf(output, "Authenticated security-patched Nebula %s (%s) for %s/%s; reproducibly staged %d files (%d bytes) in %s. No software was installed or started, and no codesigning or notarization claim was made.\n",
		result.Identity.Version, result.Identity.Commit, result.Target.OS, result.Target.Arch, result.FileCount, result.TotalBytes, result.OutputDir)
	return nil
}

func runBuildNebulaWindowsRuntime(ctx context.Context, args []string, output io.Writer) error {
	flags := flag.NewFlagSet("build-nebula-windows-runtime", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	arch := flags.String("arch", "", "locked Windows target architecture")
	outputDir := flags.String("output-dir", "", "new directory for verified files")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("build-nebula-windows-runtime does not accept positional arguments")
	}
	if strings.TrimSpace(*arch) == "" || strings.TrimSpace(*outputDir) == "" {
		return errors.New("--arch and --output-dir are required")
	}
	result, err := nebulaobserverartifact.BuildWindows(ctx, *arch, *outputDir)
	if err != nil {
		return err
	}
	fmt.Fprintf(output, "Authenticated security-patched Nebula %s (%s) for %s/%s; reproducibly staged %d files (%d bytes) in %s. No software was installed or started, and no Authenticode claim was made.\n",
		result.Identity.Version, result.Identity.Commit, result.Target.OS, result.Target.Arch, result.FileCount, result.TotalBytes, result.OutputDir)
	return nil
}

func runFetchNebula(ctx context.Context, args []string, output io.Writer) error {
	flags := flag.NewFlagSet("fetch-nebula", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	goos := flags.String("os", "", "locked target operating system")
	goarch := flags.String("arch", "", "locked target architecture")
	outputDir := flags.String("output-dir", "", "new directory for verified files")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("fetch-nebula does not accept positional arguments")
	}
	if strings.TrimSpace(*goos) == "" || strings.TrimSpace(*goarch) == "" || strings.TrimSpace(*outputDir) == "" {
		return fmt.Errorf("--os, --arch, and --output-dir are required")
	}
	result, err := nebulaartifact.FetchNebula(ctx, *goos, *goarch, *outputDir)
	if err != nil {
		return err
	}
	fmt.Fprintf(output, "Authenticated %s for %s/%s; staged %d files (%d bytes) in %s. No software was installed or started.\n", result.AssetName, result.Target.OS, result.Target.Arch, result.FileCount, result.TotalBytes, result.OutputDir)
	return nil
}

func runBuildNebulaObserver(ctx context.Context, args []string, output io.Writer) error {
	flags := flag.NewFlagSet("build-nebula-observer", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	arch := flags.String("arch", "", "locked Linux target architecture")
	outputDir := flags.String("output-dir", "", "new directory for verified files")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("build-nebula-observer does not accept positional arguments")
	}
	if strings.TrimSpace(*arch) == "" || strings.TrimSpace(*outputDir) == "" {
		return errors.New("--arch and --output-dir are required")
	}
	result, err := nebulaobserverartifact.Build(ctx, *arch, *outputDir)
	if err != nil {
		return err
	}
	fmt.Fprintf(output, "Authenticated observer-enabled Nebula %s (%s) for %s/%s; reproducibly staged %d files (%d bytes) in %s. No software was installed or started.\n",
		result.Identity.Version, result.Identity.Commit, result.Target.OS, result.Target.Arch, result.FileCount, result.TotalBytes, result.OutputDir)
	return nil
}

func usageError() error {
	return errors.New("usage: mesh-deps fetch-nebula --os <linux|darwin|windows> --arch <amd64|arm64> --output-dir <new-path> | mesh-deps build-nebula-observer --arch <amd64|arm64> --output-dir <new-path> | mesh-deps build-nebula-windows-runtime --arch <amd64|arm64> --output-dir <new-path> | mesh-deps build-nebula-darwin-runtime --arch <amd64|arm64> --output-dir <new-path>")
}
