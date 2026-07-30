package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"mesh/internal/appleapprelease"
	"mesh/internal/buildinfo"
	releasetrust "mesh/internal/release"
)

func verifyAppleAppRelease(args []string, output io.Writer) error {
	flags := flag.NewFlagSet("verify-apple-app-release", flag.ContinueOnError)
	archivePath := flags.String("archive", "", "final protected Mesh Admin ditto zip")
	receiptPath := flags.String("receipt", "", "canonical protected application release receipt")
	sourceReceiptSHA256 := flags.String("source-receipt-sha256", "", "expected unsigned source receipt SHA-256")
	teamID := flags.String("team-id", "", "expected approved Apple Developer Team ID")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("verify-apple-app-release does not accept positional arguments")
	}
	for _, required := range []struct {
		name  string
		value string
	}{
		{"--archive", *archivePath},
		{"--receipt", *receiptPath},
		{"--source-receipt-sha256", *sourceReceiptSHA256},
		{"--team-id", *teamID},
	} {
		if strings.TrimSpace(required.value) == "" {
			return fmt.Errorf("%s is required", required.name)
		}
	}
	raw, err := readRegularFile(*receiptPath, appleapprelease.MaximumReceiptSize)
	if err != nil {
		return fmt.Errorf("read protected Apple application receipt: %w", err)
	}
	receipt, err := appleapprelease.ParseReceipt(raw)
	if err != nil {
		return err
	}
	archive, err := hashStableAppleApplicationArchive(*archivePath, receipt.Distribution.Size)
	if err != nil {
		return err
	}
	if err := receipt.Match(
		time.Now().UTC(),
		archive,
		strings.TrimSpace(*sourceReceiptSHA256),
		strings.TrimSpace(*teamID),
	); err != nil {
		return err
	}
	_, err = fmt.Fprintf(
		output,
		"Verified protected Mesh Admin archive %s with Team ID %s, accepted notarization %s, validated staple, Gatekeeper acceptance, and source receipt %s. This portable receipt check does not replace native Apple signature, staple, or Gatekeeper re-verification.\n",
		receipt.Distribution.SHA256,
		receipt.Signing.TeamID,
		receipt.Notarization.SubmissionID,
		receipt.Source.ReceiptSHA256,
	)
	return err
}

func hashStableAppleApplicationArchive(path string, expectedSize int64) (appleapprelease.ArtifactIdentity, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return appleapprelease.ArtifactIdentity{}, fmt.Errorf("inspect protected Apple application archive: %w", err)
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return appleapprelease.ArtifactIdentity{}, errors.New("protected Apple application archive must be one physical regular file")
	}
	if expectedSize < 1 || before.Size() != expectedSize {
		return appleapprelease.ArtifactIdentity{}, errors.New("protected Apple application archive size differs from its receipt")
	}
	file, err := os.Open(path)
	if err != nil {
		return appleapprelease.ArtifactIdentity{}, fmt.Errorf("open protected Apple application archive: %w", err)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return appleapprelease.ArtifactIdentity{}, errors.New("protected Apple application archive changed while opening")
	}
	hasher := sha256.New()
	written, err := io.Copy(hasher, io.LimitReader(file, expectedSize+1))
	if err != nil {
		return appleapprelease.ArtifactIdentity{}, fmt.Errorf("hash protected Apple application archive: %w", err)
	}
	if written != expectedSize {
		return appleapprelease.ArtifactIdentity{}, errors.New("protected Apple application archive changed while hashing")
	}
	afterOpen, statErr := file.Stat()
	afterPath, lstatErr := os.Lstat(path)
	if statErr != nil || lstatErr != nil ||
		!os.SameFile(before, afterOpen) ||
		!os.SameFile(before, afterPath) ||
		afterOpen.Size() != before.Size() ||
		afterOpen.ModTime() != before.ModTime() ||
		afterOpen.Mode() != before.Mode() ||
		afterPath.Size() != before.Size() ||
		afterPath.ModTime() != before.ModTime() ||
		afterPath.Mode() != before.Mode() {
		return appleapprelease.ArtifactIdentity{}, errors.New("protected Apple application archive changed while hashing")
	}
	return appleapprelease.ArtifactIdentity{
		SHA256: hex.EncodeToString(hasher.Sum(nil)),
		Size:   written,
	}, nil
}

func verifyPublishedAppleApp(args []string, output io.Writer) error {
	info, err := buildinfo.Current()
	if err != nil {
		return err
	}
	flags := flag.NewFlagSet("verify-published-apple-app", flag.ContinueOnError)
	rootPath := flags.String("root", "", "independently authenticated current Mesh release root")
	rootSHA256 := flags.String("root-sha256", "", "independently authenticated current Mesh release root SHA-256")
	manifestPath := flags.String("manifest", "", "downloaded canonical Mesh release manifest")
	archivePath := flags.String("archive", "", "downloaded Mesh Admin zip")
	receiptPath := flags.String("receipt", "", "downloaded protected Mesh Admin receipt")
	sourceReceiptSHA256 := flags.String("source-receipt-sha256", "", "expected unsigned source receipt SHA-256")
	teamID := flags.String("team-id", "", "expected approved Apple Developer Team ID")
	var signaturePaths repeatedFlag
	flags.Var(&signaturePaths, "signature", "downloaded detached release signature (repeat)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("verify-published-apple-app does not accept positional arguments")
	}
	for _, required := range []struct {
		name  string
		value string
	}{
		{"--root", *rootPath},
		{"--root-sha256", *rootSHA256},
		{"--manifest", *manifestPath},
		{"--archive", *archivePath},
		{"--receipt", *receiptPath},
		{"--source-receipt-sha256", *sourceReceiptSHA256},
		{"--team-id", *teamID},
	} {
		if strings.TrimSpace(required.value) == "" {
			return fmt.Errorf("%s is required", required.name)
		}
	}
	if len(signaturePaths) == 0 {
		return errors.New("at least one --signature is required")
	}
	now := time.Now().UTC()
	rootRaw, err := readRegularFile(*rootPath, releasetrust.MaxRootSize)
	if err != nil {
		return fmt.Errorf("read trusted release root: %w", err)
	}
	rootDigest := sha256.Sum256(rootRaw)
	if strings.TrimSpace(*rootSHA256) != hex.EncodeToString(rootDigest[:]) {
		return errors.New("current release root differs from its independently authenticated SHA-256")
	}
	root, err := releasetrust.ParseRoot(rootRaw)
	if err != nil {
		return err
	}
	if err := releasetrust.ValidateCurrentRoot(root, now, 0); err != nil {
		return fmt.Errorf("current trusted release root: %w", err)
	}
	manifestRaw, err := readRegularFile(*manifestPath, releasetrust.MaxManifestSize)
	if err != nil {
		return fmt.Errorf("read downloaded release manifest: %w", err)
	}
	signatures := make([][]byte, 0, len(signaturePaths))
	for _, path := range signaturePaths {
		raw, err := readRegularFile(path, releasetrust.MaxEnvelopeSize)
		if err != nil {
			return fmt.Errorf("read downloaded release signature %q: %w", path, err)
		}
		signatures = append(signatures, raw)
	}
	verified, err := releasetrust.VerifyManifest(
		manifestRaw,
		signatures,
		root.ReleaseKeys,
		releasetrust.VerificationPolicy{
			Now:                    now,
			Threshold:              root.Document.Roles.Release.Threshold,
			MinimumSequence:        root.Document.MinimumReleaseSequence,
			MinimumSecurityFloor:   root.Document.MinimumSecurityFloor,
			SupportedSecurityFloor: info.SecurityFloor,
			ExpectedChannel:        root.Document.Channel,
			ExpectedReleaseEpoch:   root.Document.ReleaseEpoch,
			MinimumReleaseEpoch:    root.Document.ReleaseEpoch,
		},
	)
	if err != nil {
		return err
	}
	if verified.Kind != releasetrust.ReleaseManifestKind || verified.Release == nil {
		return errors.New("published Mesh Admin evidence requires one authenticated release manifest")
	}
	application, evidence, err := publishedAppleAppArtifacts(verified.Release.Artifacts)
	if err != nil {
		return err
	}
	if err := releasetrust.VerifyArtifactFile(*archivePath, application); err != nil {
		return fmt.Errorf("verify published Mesh Admin archive: %w", err)
	}
	receiptRaw, err := readRegularFile(*receiptPath, appleapprelease.MaximumReceiptSize)
	if err != nil {
		return fmt.Errorf("read published Mesh Admin receipt: %w", err)
	}
	if err := releasetrust.VerifyArtifact(bytes.NewReader(receiptRaw), evidence); err != nil {
		return fmt.Errorf("verify published Mesh Admin receipt: %w", err)
	}
	receipt, err := appleapprelease.ParseReceipt(receiptRaw)
	if err != nil {
		return err
	}
	if receipt.Application.Version != verified.Release.Version {
		return errors.New("published Mesh Admin receipt version differs from authenticated release metadata")
	}
	archive, err := hashStableAppleApplicationArchive(*archivePath, application.Size)
	if err != nil {
		return err
	}
	if err := receipt.Match(
		now,
		archive,
		strings.TrimSpace(*sourceReceiptSHA256),
		strings.TrimSpace(*teamID),
	); err != nil {
		return err
	}
	_, err = fmt.Fprintf(
		output,
		"Verified downloaded Mesh Admin archive %s and protected receipt %s against release %s, channel %s, epoch %d, sequence %d, and %d trusted release signatures from the independently authenticated root. Native Apple signature, staple, Gatekeeper, and offline checks are still required.\n",
		application.SHA256,
		evidence.SHA256,
		verified.Release.Version,
		verified.Release.Channel,
		verified.Release.ReleaseEpoch,
		verified.Release.Sequence,
		len(verified.SignerKeyIDs),
	)
	return err
}

func publishedAppleAppArtifacts(artifacts []releasetrust.Artifact) (releasetrust.Artifact, releasetrust.Artifact, error) {
	var application releasetrust.Artifact
	var evidence releasetrust.Artifact
	for _, artifact := range artifacts {
		switch {
		case artifact.OS == "macos-admin" && artifact.Arch == "universal":
			application = artifact
		case artifact.OS == "macos-admin-evidence" && artifact.Arch == "portable":
			evidence = artifact
		}
	}
	if application.OS == "" || evidence.OS == "" {
		return releasetrust.Artifact{}, releasetrust.Artifact{}, errors.New("authenticated release lacks the exact Mesh Admin archive/evidence pair")
	}
	return application, evidence, nil
}
