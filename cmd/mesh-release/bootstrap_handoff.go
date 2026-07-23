package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"mesh/internal/bootstraphandoffauthor"
	releasetrust "mesh/internal/release"
	"mesh/internal/verifierbundle"
)

func createBootstrapHandoff(args []string, output io.Writer) error {
	flags := flag.NewFlagSet("create-bootstrap-handoff", flag.ContinueOnError)
	outputPath := flags.String("output", "", "new canonical bootstrap handoff (never overwritten)")
	rootPath := flags.String("root", "", "canonical version-1, epoch-1 release root")
	issuedText := flags.String("issued", "", "canonical UTC RFC3339 issue time")
	expiresText := flags.String("expires", "", "canonical UTC RFC3339 expiration time")
	var verifierPaths repeatedFlag
	flags.Var(&verifierPaths, "verifier-package", "canonical deterministic verifier USTAR (exactly linux/windows amd64/arm64)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("create-bootstrap-handoff does not accept positional arguments")
	}
	if strings.TrimSpace(*outputPath) == "" || strings.TrimSpace(*rootPath) == "" || strings.TrimSpace(*issuedText) == "" || strings.TrimSpace(*expiresText) == "" || len(verifierPaths) != 4 {
		return errors.New("--output, --root, --issued, --expires, and exactly four --verifier-package values are required")
	}
	rootRaw, err := readAuthoringPublicFile("bootstrap root", *rootPath, releasetrust.MaxRootSize)
	if err != nil {
		return fmt.Errorf("read bootstrap root: %w", err)
	}
	inspections := make([]verifierbundle.Inspection, 0, len(verifierPaths))
	for _, path := range verifierPaths {
		inspection, err := verifierbundle.InspectFile(path)
		if err != nil {
			return fmt.Errorf("inspect bootstrap verifier package %q: %w", path, err)
		}
		inspections = append(inspections, inspection)
	}
	document, raw, err := bootstraphandoffauthor.Create(rootRaw, inspections, strings.TrimSpace(*issuedText), strings.TrimSpace(*expiresText))
	if err != nil {
		return err
	}
	if err := writeAuthoringPublicFile("bootstrap handoff", *outputPath, raw, 0o644); err != nil {
		return err
	}
	digest := sha256.Sum256(raw)
	_, err = fmt.Fprintf(output,
		"Created unsigned canonical %s bootstrap handoff SHA-256 %s binding root SHA-256 %s and all four Linux/Windows verifier packages at %s. Authenticate this handoff digest through the independent operator channel; no signature or trust was created.\n",
		document.Channel, hex.EncodeToString(digest[:]), document.Root.SHA256, *outputPath)
	return err
}
