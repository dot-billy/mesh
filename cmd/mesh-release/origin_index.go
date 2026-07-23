package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"

	"mesh/internal/releaseorigin"
)

func createOriginIndex(arguments []string, output io.Writer) error {
	flags := flag.NewFlagSet("create-origin-index", flag.ContinueOnError)
	root := flags.String("root", "", "clean absolute directory containing only public release objects")
	outputPath := flags.String("output", "", "new canonical release-origin index (never overwritten)")
	var objects repeatedFlag
	flags.Var(&objects, "object", "canonical absolute URL path to one object below root (repeat)")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("create-origin-index does not accept positional arguments")
	}
	if *root == "" || *outputPath == "" || len(objects) == 0 {
		return errors.New("--root, --output, and at least one --object are required")
	}
	index, err := releaseorigin.BuildIndex(*root, objects)
	if err != nil {
		return err
	}
	raw, err := releaseorigin.Encode(index)
	if err != nil {
		return err
	}
	if err := releaseorigin.WriteNewIndex(*outputPath, raw); err != nil {
		return err
	}
	digest := sha256.Sum256(raw)
	_, err = fmt.Fprintf(output, "Created release-origin index %s with %d explicitly published objects and SHA-256 %s. No release metadata was trusted and no object was modified.\n",
		*outputPath, len(index.Objects), hex.EncodeToString(digest[:]))
	return err
}
