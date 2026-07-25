package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"mesh/internal/bootstrapanchorauthor"
	"mesh/internal/bootstraphandoff"
)

func createBootstrapAnchor(args []string, output io.Writer) error {
	flags := flag.NewFlagSet("create-bootstrap-anchor", flag.ContinueOnError)
	handoffPath := flags.String("handoff", "", "canonical bootstrap handoff to review and bind")
	outputPath := flags.String("output", "", "new canonical bootstrap anchor (never overwritten)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("create-bootstrap-anchor does not accept positional arguments")
	}
	if strings.TrimSpace(*handoffPath) == "" || strings.TrimSpace(*outputPath) == "" {
		return errors.New("--handoff and --output are required")
	}
	handoffRaw, err := readAuthoringPublicFile("bootstrap handoff", *handoffPath, bootstraphandoff.MaxDocumentSize)
	if err != nil {
		return fmt.Errorf("read bootstrap handoff: %w", err)
	}
	document, raw, err := bootstrapanchorauthor.Create(handoffRaw)
	if err != nil {
		return fmt.Errorf("create bootstrap anchor: %w", err)
	}
	if err := writeAuthoringPublicFile("bootstrap anchor", *outputPath, raw, 0o644); err != nil {
		return err
	}
	digest := sha256.Sum256(raw)
	_, err = fmt.Fprintf(output,
		"Created unsigned canonical %s bootstrap anchor SHA-256 %s for handoff SHA-256 %s, channel %s, expiring %s at %s. Transfer this file independently and keep it off the release origin; no signature or trust was created by writing it.\n",
		document.Schema, hex.EncodeToString(digest[:]), document.Handoff.SHA256, document.Channel, document.Handoff.ExpiresAt, *outputPath)
	return err
}
