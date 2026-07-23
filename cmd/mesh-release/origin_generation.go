package main

import (
	"errors"
	"flag"
	"fmt"
	"io"

	"mesh/internal/releaseorigin"
)

func publishOriginGeneration(arguments []string, output io.Writer) error {
	flags := flag.NewFlagSet("publish-origin-generation", flag.ContinueOnError)
	sourceRoot := flags.String("source-root", "", "clean absolute staging repository containing public release objects")
	indexPath := flags.String("index", "", "clean absolute canonical release-origin index")
	generationsRoot := flags.String("generations-root", "", "existing clean absolute operator-controlled generation directory")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("publish-origin-generation does not accept positional arguments")
	}
	if *sourceRoot == "" || *indexPath == "" || *generationsRoot == "" {
		return errors.New("--source-root, --index, and --generations-root are required")
	}
	receipt, generationPath, err := releaseorigin.PublishGeneration(*sourceRoot, *indexPath, *generationsRoot)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(output, "Published release-origin generation %s with %d objects, %d bytes, and index SHA-256 %s. No source object was modified and no release metadata was trusted.\n",
		generationPath, receipt.ObjectCount, receipt.TotalSize, receipt.IndexSHA256)
	return err
}

func inspectOriginGeneration(arguments []string, output io.Writer) error {
	flags := flag.NewFlagSet("inspect-origin-generation", flag.ContinueOnError)
	generationPath := flags.String("generation", "", "clean absolute release-origin generation directory")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("inspect-origin-generation does not accept positional arguments")
	}
	if *generationPath == "" {
		return errors.New("--generation is required")
	}
	receipt, err := releaseorigin.InspectGeneration(*generationPath)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(output, "Validated release-origin generation %s with %d objects, %d bytes, and index SHA-256 %s. The generation is a courier, not release authority.\n",
		*generationPath, receipt.ObjectCount, receipt.TotalSize, receipt.IndexSHA256)
	return err
}
