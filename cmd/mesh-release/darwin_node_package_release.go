package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"mesh/internal/darwincodesign"
	"mesh/internal/darwinnodepackage"
)

var (
	loadDarwinNodePackageReleasePolicy = darwinnodepackage.LoadPolicy
	loadDarwinNodeCodesignPolicy       = darwincodesign.LoadPolicy
)

func verifyDarwinNodePackageRelease(args []string, output io.Writer) error {
	flags := flag.NewFlagSet("verify-darwin-node-package-release", flag.ContinueOnError)
	packagePath := flags.String("package", "", "final signed, notarized, and stapled Mesh Node package")
	receiptPath := flags.String("receipt", "", "canonical protected node-package release receipt")
	architecture := flags.String("arch", "", "exact package architecture")
	version := flags.String("version", "", "exact package version")
	codesignReceiptSHA256 := flags.String("codesign-receipt-sha256", "", "expected native code-signing receipt SHA-256")
	bundleSecurityReceiptSHA256 := flags.String("bundle-security-receipt-sha256", "", "expected final bundle-security receipt SHA-256")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("verify-darwin-node-package-release does not accept positional arguments")
	}
	for _, required := range []struct {
		name  string
		value string
	}{
		{"--package", *packagePath},
		{"--receipt", *receiptPath},
		{"--arch", *architecture},
		{"--version", *version},
		{"--codesign-receipt-sha256", *codesignReceiptSHA256},
		{"--bundle-security-receipt-sha256", *bundleSecurityReceiptSHA256},
	} {
		if strings.TrimSpace(required.value) == "" {
			return fmt.Errorf("%s is required", required.name)
		}
	}
	packagePolicy, err := loadDarwinNodePackageReleasePolicy()
	if err != nil {
		return fmt.Errorf("load compiled Darwin node package policy: %w", err)
	}
	codesignPolicy, err := loadDarwinNodeCodesignPolicy()
	if err != nil {
		return fmt.Errorf("load compiled Darwin code-signing policy: %w", err)
	}
	raw, err := readRegularFile(*receiptPath, darwinnodepackage.MaximumReceiptSize)
	if err != nil {
		return fmt.Errorf("read protected Darwin node package receipt: %w", err)
	}
	receipt, err := darwinnodepackage.ParseReleaseReceipt(raw)
	if err != nil {
		return err
	}
	artifact, err := hashStableDarwinNodePackage(*packagePath, receipt.Package.Size)
	if err != nil {
		return err
	}
	if err := receipt.MatchForPublication(
		time.Now().UTC(), artifact, packagePolicy,
		codesignPolicy.SHA256, codesignPolicy.MeshInstallIdentifier,
		strings.TrimSpace(*architecture), strings.TrimSpace(*version),
		codesignPolicy.TeamID, strings.TrimSpace(*codesignReceiptSHA256),
		strings.TrimSpace(*bundleSecurityReceiptSHA256),
	); err != nil {
		return err
	}
	_, err = fmt.Fprintf(
		output,
		"Verified protected Mesh Node package %s for darwin/%s with Team ID %s, accepted notarization %s, validated staple, Gatekeeper acceptance, and exact package/code-signing policies. This portable receipt check does not replace native package signature, contents, staple, or Gatekeeper re-verification.\n",
		receipt.Package.SHA256,
		receipt.Package.Architecture,
		receipt.Signing.TeamID,
		receipt.Notarization.SubmissionID,
	)
	return err
}

func hashStableDarwinNodePackage(path string, expectedSize int64) (darwinnodepackage.PackageArtifactIdentity, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return darwinnodepackage.PackageArtifactIdentity{}, fmt.Errorf("inspect protected Darwin node package: %w", err)
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return darwinnodepackage.PackageArtifactIdentity{}, errors.New("protected Darwin node package must be one physical regular file")
	}
	if expectedSize < 1 || before.Size() != expectedSize {
		return darwinnodepackage.PackageArtifactIdentity{}, errors.New("protected Darwin node package size differs from its receipt")
	}
	file, err := os.Open(path)
	if err != nil {
		return darwinnodepackage.PackageArtifactIdentity{}, fmt.Errorf("open protected Darwin node package: %w", err)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return darwinnodepackage.PackageArtifactIdentity{}, errors.New("protected Darwin node package changed while opening")
	}
	hasher := sha256.New()
	written, err := io.Copy(hasher, io.LimitReader(file, expectedSize+1))
	if err != nil || written != expectedSize {
		return darwinnodepackage.PackageArtifactIdentity{}, errors.Join(err, errors.New("protected Darwin node package changed while hashing"))
	}
	afterOpen, statErr := file.Stat()
	afterPath, lstatErr := os.Lstat(path)
	if statErr != nil || lstatErr != nil ||
		!os.SameFile(before, afterOpen) || !os.SameFile(before, afterPath) ||
		afterOpen.Size() != before.Size() || afterPath.Size() != before.Size() ||
		afterOpen.ModTime() != before.ModTime() || afterPath.ModTime() != before.ModTime() ||
		afterOpen.Mode() != before.Mode() || afterPath.Mode() != before.Mode() {
		return darwinnodepackage.PackageArtifactIdentity{}, errors.New("protected Darwin node package changed while hashing")
	}
	return darwinnodepackage.PackageArtifactIdentity{
		SHA256: hex.EncodeToString(hasher.Sum(nil)),
		Size:   written,
	}, nil
}
