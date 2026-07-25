package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	releasetrust "mesh/internal/release"
)

func createRoot(args []string, output io.Writer) error {
	flags := flag.NewFlagSet("create-root", flag.ContinueOnError)
	outputPath := flags.String("output", "", "new canonical root document (never overwritten)")
	previousPath := flags.String("previous-root", "", "optional canonical immediate predecessor")
	channel := flags.String("channel", "", "initial canonical release channel; derived for successors")
	releaseEpoch := flags.Uint64("release-epoch", 0, "positive release epoch; defaults to predecessor epoch")
	minimumSequence := flags.Uint64("minimum-release-sequence", 0, "positive release sequence floor; defaults to predecessor floor")
	minimumFloor := flags.Uint64("minimum-security-floor", 0, "positive security floor; defaults to predecessor floor")
	issuedAt := flags.String("issued", "", "canonical UTC RFC3339 issue time")
	expiresAt := flags.String("expires", "", "canonical UTC RFC3339 expiration time")
	rootThreshold := flags.Int("root-threshold", 0, "root role threshold; defaults to predecessor threshold")
	releaseThreshold := flags.Int("release-threshold", 0, "release role threshold; defaults to predecessor threshold")
	var rootPaths repeatedFlag
	var releasePaths repeatedFlag
	flags.Var(&rootPaths, "root-public", "root-role Ed25519 public key (repeat)")
	flags.Var(&releasePaths, "release-public", "release-role Ed25519 public key (repeat)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("create-root does not accept positional arguments")
	}
	if strings.TrimSpace(*outputPath) == "" || strings.TrimSpace(*issuedAt) == "" || strings.TrimSpace(*expiresAt) == "" {
		return errors.New("--output, --issued, and --expires are required")
	}
	if len(rootPaths) == 0 || len(releasePaths) == 0 {
		return errors.New("at least one --root-public and --release-public are required")
	}
	rootFiles, err := readRootPublicFiles(rootPaths)
	if err != nil {
		return fmt.Errorf("root role: %w", err)
	}
	releaseFiles, err := readRootPublicFiles(releasePaths)
	if err != nil {
		return fmt.Errorf("release role: %w", err)
	}
	document := releasetrust.Root{
		Schema: releasetrust.RootSchema, Channel: strings.TrimSpace(*channel),
		ReleaseEpoch: *releaseEpoch, MinimumReleaseSequence: *minimumSequence,
		MinimumSecurityFloor: *minimumFloor, IssuedAt: strings.TrimSpace(*issuedAt), ExpiresAt: strings.TrimSpace(*expiresAt),
		Keys: append(append([]releasetrust.PublicKeyFile(nil), rootFiles...), releaseFiles...),
		Roles: releasetrust.RootRoles{
			Root:    releasetrust.RootRole{Threshold: *rootThreshold, KeyIDs: rootKeyIDs(rootFiles)},
			Release: releasetrust.RootRole{Threshold: *releaseThreshold, KeyIDs: rootKeyIDs(releaseFiles)},
		},
	}
	var previous *releasetrust.ParsedRoot
	if strings.TrimSpace(*previousPath) == "" {
		document.Version = 1
		if document.ReleaseEpoch == 0 {
			document.ReleaseEpoch = 1
		}
	} else {
		raw, err := readAuthoringPublicFile("previous root", *previousPath, releasetrust.MaxRootSize)
		if err != nil {
			return fmt.Errorf("read previous root: %w", err)
		}
		parsed, err := releasetrust.ParseRoot(raw)
		if err != nil {
			return fmt.Errorf("parse previous root: %w", err)
		}
		previous = &parsed
		if parsed.Document.Version == ^uint64(0) {
			return errors.New("previous root version is terminal")
		}
		document.Version = parsed.Document.Version + 1
		if document.Channel == "" {
			document.Channel = parsed.Document.Channel
		}
		if document.ReleaseEpoch == 0 {
			document.ReleaseEpoch = parsed.Document.ReleaseEpoch
		}
		if document.MinimumReleaseSequence == 0 {
			document.MinimumReleaseSequence = parsed.Document.MinimumReleaseSequence
		}
		if document.MinimumSecurityFloor == 0 {
			document.MinimumSecurityFloor = parsed.Document.MinimumSecurityFloor
		}
		if document.Roles.Root.Threshold == 0 {
			document.Roles.Root.Threshold = parsed.Document.Roles.Root.Threshold
		}
		if document.Roles.Release.Threshold == 0 {
			document.Roles.Release.Threshold = parsed.Document.Roles.Release.Threshold
		}
	}
	raw, err := releasetrust.EncodeRoot(document)
	if err != nil {
		return err
	}
	parsed, err := releasetrust.ParseRoot(raw)
	if err != nil {
		return err
	}
	if previous != nil {
		if err := releasetrust.ValidateRootSuccessor(*previous, parsed); err != nil {
			return err
		}
	}
	if err := writeAuthoringPublicFile("release root", *outputPath, raw, 0o644); err != nil {
		return err
	}
	_, err = fmt.Fprintf(output, "Created canonical release root version %d, release epoch %d, SHA-256 %s at %s. No key was trusted or software installed.\n", parsed.Document.Version, parsed.Document.ReleaseEpoch, parsed.SHA256, *outputPath)
	return err
}

func inspectRoot(args []string, output io.Writer) error {
	flags := flag.NewFlagSet("inspect-root", flag.ContinueOnError)
	rootPath := flags.String("root", "", "canonical root document")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || strings.TrimSpace(*rootPath) == "" {
		return errors.New("inspect-root requires exactly --root and no positional arguments")
	}
	raw, err := readAuthoringPublicFile("release root", *rootPath, releasetrust.MaxRootSize)
	if err != nil {
		return err
	}
	root, err := releasetrust.ParseRoot(raw)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(output, "Release root version %d, release epoch %d, channel %s, root threshold %d/%d, release threshold %d/%d, expires %s, SHA-256 %s.\n",
		root.Document.Version, root.Document.ReleaseEpoch, root.Document.Channel,
		root.Document.Roles.Root.Threshold, len(root.Document.Roles.Root.KeyIDs),
		root.Document.Roles.Release.Threshold, len(root.Document.Roles.Release.KeyIDs),
		root.Document.ExpiresAt, root.SHA256)
	return err
}

func assembleRootUpdate(args []string, output io.Writer) error {
	flags := flag.NewFlagSet("assemble-root-update", flag.ContinueOnError)
	outputPath := flags.String("output", "", "new canonical root-update envelope (never overwritten)")
	previousPath := flags.String("previous-root", "", "canonical trusted predecessor root")
	rootPath := flags.String("root", "", "canonical immediate successor root")
	var signaturePaths repeatedFlag
	flags.Var(&signaturePaths, "signature", "detached root signature (repeat)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("assemble-root-update does not accept positional arguments")
	}
	if strings.TrimSpace(*outputPath) == "" || strings.TrimSpace(*previousPath) == "" || strings.TrimSpace(*rootPath) == "" || len(signaturePaths) == 0 {
		return errors.New("--output, --previous-root, --root, and at least one --signature are required")
	}
	previousRaw, err := readAuthoringPublicFile("previous root", *previousPath, releasetrust.MaxRootSize)
	if err != nil {
		return fmt.Errorf("read previous root: %w", err)
	}
	previous, err := releasetrust.ParseRoot(previousRaw)
	if err != nil {
		return fmt.Errorf("parse previous root: %w", err)
	}
	rootRaw, err := readAuthoringPublicFile("successor root", *rootPath, releasetrust.MaxRootSize)
	if err != nil {
		return fmt.Errorf("read successor root: %w", err)
	}
	signatures := make([][]byte, len(signaturePaths))
	for index, path := range signaturePaths {
		signature, err := readAuthoringPublicFile("root signature", path, releasetrust.MaxEnvelopeSize)
		if err != nil {
			return fmt.Errorf("read root signature %d: %w", index, err)
		}
		signatures[index] = signature
	}
	transition, err := releasetrust.VerifyRootTransition(previous, rootRaw, signatures)
	if err != nil {
		return err
	}
	updateRaw, err := releasetrust.EncodeRootUpdate(releasetrust.RootUpdate{RootManifest: rootRaw, Signatures: signatures})
	if err != nil {
		return err
	}
	if err := writeAuthoringPublicFile("root update", *outputPath, updateRaw, 0o644); err != nil {
		return err
	}
	_, err = fmt.Fprintf(output, "Assembled root update to version %d with %d previous-root and %d new-root signers at %s.\n",
		transition.Root.Document.Version, len(transition.PreviousSignerKeyIDs), len(transition.NewSignerKeyIDs), *outputPath)
	return err
}

func readRootPublicFiles(paths []string) ([]releasetrust.PublicKeyFile, error) {
	files := make([]releasetrust.PublicKeyFile, len(paths))
	for index, path := range paths {
		raw, err := readAuthoringPublicFile("role public key", path, releasetrust.MaxKeyFileSize)
		if err != nil {
			return nil, fmt.Errorf("read public key %d: %w", index, err)
		}
		if _, err := releasetrust.ParseTrustedPublicKey(raw); err != nil {
			return nil, fmt.Errorf("parse public key %d: %w", index, err)
		}
		if err := json.Unmarshal(raw, &files[index]); err != nil {
			return nil, fmt.Errorf("decode public key %d: %w", index, err)
		}
	}
	return files, nil
}

func rootKeyIDs(files []releasetrust.PublicKeyFile) []string {
	result := make([]string, len(files))
	for index, file := range files {
		result[index] = file.KeyID
	}
	return result
}
