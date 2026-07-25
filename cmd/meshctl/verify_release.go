package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"time"

	"mesh/internal/buildinfo"
	releasetrust "mesh/internal/release"
)

type repeatedString []string

func (values *repeatedString) String() string { return strings.Join(*values, ",") }

func (values *repeatedString) Set(value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("path cannot be empty")
	}
	*values = append(*values, value)
	return nil
}

func verifyRelease(args []string) error {
	return verifyReleaseTo(args, os.Stdout)
}

func verifyReleaseTo(args []string, output io.Writer) error {
	info, err := buildinfo.Current()
	if err != nil {
		return err
	}
	flags := flag.NewFlagSet("verify-release", flag.ContinueOnError)
	manifestPath := flags.String("manifest", "", "local channel or release manifest")
	artifactPath := flags.String("artifact", "", "optional local artifact to stream and verify")
	threshold := flags.Int("threshold", releasetrust.DefaultThreshold, "required number of distinct trusted signatures")
	minimumSequence := flags.Uint64("minimum-sequence", 0, "persisted anti-replay sequence floor")
	minimumFloor := flags.Uint64("minimum-security-floor", info.SecurityFloor, "persisted anti-downgrade security floor")
	expectedChannel := flags.String("channel", "", "expected release channel")
	platformOS := flags.String("os", runtime.GOOS, "artifact operating system")
	platformArch := flags.String("arch", runtime.GOARCH, "artifact architecture")
	var signaturePaths repeatedString
	var trustedKeyPaths repeatedString
	flags.Var(&signaturePaths, "signature", "detached signature envelope (repeat for each signer)")
	flags.Var(&trustedKeyPaths, "trusted-public-key", "trusted Ed25519 public key file (repeat for each key)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("verify-release does not accept positional arguments")
	}
	if strings.TrimSpace(*manifestPath) == "" {
		return fmt.Errorf("--manifest is required")
	}
	if len(signaturePaths) == 0 {
		return fmt.Errorf("at least one --signature is required")
	}
	if len(trustedKeyPaths) == 0 {
		return fmt.Errorf("at least one --trusted-public-key is required")
	}
	rawManifest, err := readBoundedRegular(*manifestPath, releasetrust.MaxManifestSize)
	if err != nil {
		return fmt.Errorf("read manifest: %w", err)
	}
	rawSignatures := make([][]byte, 0, len(signaturePaths))
	for _, path := range signaturePaths {
		raw, err := readBoundedRegular(path, releasetrust.MaxEnvelopeSize)
		if err != nil {
			return fmt.Errorf("read signature %q: %w", path, err)
		}
		rawSignatures = append(rawSignatures, raw)
	}
	trustedKeys := make([]releasetrust.TrustedKey, 0, len(trustedKeyPaths))
	for _, path := range trustedKeyPaths {
		raw, err := readBoundedRegular(path, releasetrust.MaxKeyFileSize)
		if err != nil {
			return fmt.Errorf("read trusted public key %q: %w", path, err)
		}
		key, err := releasetrust.ParseTrustedPublicKey(raw)
		if err != nil {
			return fmt.Errorf("parse trusted public key %q: %w", path, err)
		}
		trustedKeys = append(trustedKeys, key)
	}
	verified, err := releasetrust.VerifyManifest(rawManifest, rawSignatures, trustedKeys, releasetrust.VerificationPolicy{
		Now:                    time.Now(),
		Threshold:              *threshold,
		MinimumSequence:        *minimumSequence,
		MinimumSecurityFloor:   *minimumFloor,
		SupportedSecurityFloor: info.SecurityFloor,
		ExpectedChannel:        strings.TrimSpace(*expectedChannel),
		PlatformOS:             strings.TrimSpace(*platformOS),
		PlatformArch:           strings.TrimSpace(*platformArch),
	})
	if err != nil {
		return err
	}
	var success string
	switch verified.Kind {
	case releasetrust.ChannelManifestKind:
		if *artifactPath != "" {
			return fmt.Errorf("--artifact requires a release manifest")
		}
		success = fmt.Sprintf("Verified channel %s sequence %d with %d distinct trusted signatures.\n", verified.Channel.Channel, verified.Channel.Sequence, len(verified.SignerKeyIDs))
	case releasetrust.ReleaseManifestKind:
		if *artifactPath != "" {
			if verified.SelectedArtifact == nil {
				return fmt.Errorf("release did not select an artifact for %s/%s", *platformOS, *platformArch)
			}
			if err := releasetrust.VerifyArtifactFile(*artifactPath, *verified.SelectedArtifact); err != nil {
				return err
			}
		}
		success = fmt.Sprintf("Verified release %s for channel %s sequence %d with %d distinct trusted signatures.\n", verified.Release.Version, verified.Release.Channel, verified.Release.Sequence, len(verified.SignerKeyIDs))
		if *artifactPath != "" {
			success += fmt.Sprintf("Verified artifact %s (%d bytes, SHA-256 %s).\n", *artifactPath, verified.SelectedArtifact.Size, verified.SelectedArtifact.SHA256)
		}
	default:
		return fmt.Errorf("unsupported verified manifest type %q", verified.Kind)
	}
	if _, err := io.WriteString(output, success); err != nil {
		return fmt.Errorf("write verification result: %w", err)
	}
	return nil
}

func readBoundedRegular(path string, limit int) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return nil, fmt.Errorf("must be a regular file, not a symlink")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	after, statErr := file.Stat()
	if statErr != nil || !os.SameFile(before, after) {
		_ = file.Close()
		return nil, fmt.Errorf("file changed while opening")
	}
	raw, readErr := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	closeErr := file.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if len(raw) > limit {
		return nil, fmt.Errorf("file exceeds %d-byte limit", limit)
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("file is empty")
	}
	return raw, nil
}
