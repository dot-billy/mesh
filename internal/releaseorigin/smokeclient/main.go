// Command smokeclient exercises the exact production online-release client and
// threshold verifier without installing an artifact. It is built only by the
// self-cleaning release-origin proof.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"time"

	"mesh/internal/onlinerelease"
	releasetrust "mesh/internal/release"
)

type repeatedPath []string

func (paths *repeatedPath) String() string { return fmt.Sprint([]string(*paths)) }
func (paths *repeatedPath) Set(value string) error {
	if value == "" {
		return errors.New("path cannot be empty")
	}
	*paths = append(*paths, value)
	return nil
}

func main() {
	flags := flag.NewFlagSet("mesh-origin-smokeclient", flag.ExitOnError)
	bundleURL := flags.String("bundle-url", "", "canonical HTTPS online bundle URL")
	output := flags.String("output", "", "new downloaded artifact path")
	var keyPaths repeatedPath
	flags.Var(&keyPaths, "release-public", "trusted release-role public key (repeat)")
	flags.Parse(os.Args[1:])
	if flags.NArg() != 0 || *bundleURL == "" || *output == "" || len(keyPaths) != 2 {
		fatal(errors.New("--bundle-url, --output, and exactly two --release-public files are required"))
	}
	trusted := make([]releasetrust.TrustedKey, len(keyPaths))
	for index, path := range keyPaths {
		raw, err := os.ReadFile(path)
		if err != nil {
			fatal(errors.New("read release public key"))
		}
		trusted[index], err = releasetrust.ParseTrustedPublicKey(raw)
		if err != nil {
			fatal(fmt.Errorf("parse release public key: %w", err))
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client := onlinerelease.NewClient()
	bundle, err := client.FetchBundle(ctx, *bundleURL)
	if err != nil {
		fatal(err)
	}
	policy := releasetrust.VerificationPolicy{
		Now: time.Now().UTC(), Threshold: 2, MinimumSequence: 1,
		MinimumSecurityFloor: 1, SupportedSecurityFloor: 1,
		ExpectedChannel: "stable", ExpectedReleaseEpoch: 1, MinimumReleaseEpoch: 1,
		PlatformOS: runtime.GOOS, PlatformArch: runtime.GOARCH,
	}
	_, release, err := releasetrust.VerifyChannelRelease(
		bundle.ChannelManifest, bundle.ChannelSignatures,
		bundle.ReleaseManifest, bundle.ReleaseSignatures,
		trusted, policy,
	)
	if err != nil {
		fatal(fmt.Errorf("verify threshold-authenticated release: %w", err))
	}
	if release.SelectedArtifact == nil {
		fatal(errors.New("verified release selected no artifact"))
	}
	file, err := os.OpenFile(*output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		fatal(errors.New("create artifact output"))
	}
	if err := client.FetchArtifact(ctx, *release.SelectedArtifact, file); err != nil {
		_ = file.Close()
		_ = os.Remove(*output)
		fatal(err)
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(*output)
		fatal(errors.New("close artifact output"))
	}
	_, _ = io.WriteString(os.Stdout, "verified threshold-authenticated release and downloaded exact artifact\n")
}

func fatal(err error) {
	_, _ = fmt.Fprintln(os.Stderr, "mesh-origin-smokeclient:", err)
	os.Exit(1)
}
