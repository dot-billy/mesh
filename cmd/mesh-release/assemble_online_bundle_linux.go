//go:build linux

package main

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"mesh/internal/onlinerelease"
	releasetrust "mesh/internal/release"
)

const onlineBundleOutputMode = 0o644

type onlineBundleAssemblyOptions struct {
	outputPath            string
	rootUpdatePaths       []string
	channelManifestPath   string
	channelSignaturePaths []string
	releaseManifestPath   string
	releaseSignaturePaths []string
}

// onlineBundleAssemblyHooks exposes deterministic race seams to this
// package's tests. Production uses no hooks.
type onlineBundleAssemblyHooks struct {
	afterInputRead func(path string)
	beforePublish  func()
}

func assembleOnlineBundle(args []string, output io.Writer) error {
	flags := flag.NewFlagSet("assemble-online-bundle", flag.ContinueOnError)
	outputPath := flags.String("output", "", "new public online release bundle (created 0644, never overwritten)")
	channelManifest := flags.String("channel-manifest", "", "exact signed channel manifest")
	releaseManifest := flags.String("release-manifest", "", "exact signed release manifest")
	var channelSignatures repeatedFlag
	var releaseSignatures repeatedFlag
	var rootUpdates repeatedFlag
	flags.Var(&rootUpdates, "root-update", "canonical root-update envelope to carry (repeat; sorted by root version)")
	flags.Var(&channelSignatures, "channel-signature", "detached channel signature envelope (repeat for each signer)")
	flags.Var(&releaseSignatures, "release-signature", "detached release signature envelope (repeat for each signer)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("assemble-online-bundle does not accept positional arguments")
	}
	options := onlineBundleAssemblyOptions{
		outputPath:            *outputPath,
		rootUpdatePaths:       append([]string(nil), rootUpdates...),
		channelManifestPath:   *channelManifest,
		channelSignaturePaths: append([]string(nil), channelSignatures...),
		releaseManifestPath:   *releaseManifest,
		releaseSignaturePaths: append([]string(nil), releaseSignatures...),
	}
	if err := assembleOnlineBundleUsing(options, onlineBundleAssemblyHooks{}); err != nil {
		return err
	}
	_, err := fmt.Fprintf(output, "Assembled unsigned online release bundle %s. No metadata was trusted and no software was installed or started.\n", options.outputPath)
	return err
}

func assembleOnlineBundleUsing(options onlineBundleAssemblyOptions, hooks onlineBundleAssemblyHooks) error {
	if err := validateMetadataAssemblyOptions(
		options.outputPath,
		options.channelManifestPath,
		options.channelSignaturePaths,
		options.releaseManifestPath,
		options.releaseSignaturePaths,
	); err != nil {
		return err
	}
	if len(options.rootUpdatePaths) > releasetrust.MaxRootUpdatesPerInput {
		return fmt.Errorf("--root-update count must not exceed %d", releasetrust.MaxRootUpdatesPerInput)
	}

	specs := make([]snapshotInputSpec, 0, len(options.rootUpdatePaths)+2+len(options.channelSignaturePaths)+len(options.releaseSignaturePaths))
	for _, path := range options.rootUpdatePaths {
		specs = append(specs, snapshotInputSpec{role: "root update", path: path, limit: releasetrust.MaxRootUpdateSize})
	}
	specs = append(specs, metadataInputSpecs(
		options.channelManifestPath,
		options.channelSignaturePaths,
		options.releaseManifestPath,
		options.releaseSignaturePaths,
	)...)
	inputs, err := openSnapshotInputs(specs)
	if err != nil {
		return err
	}
	defer closeSnapshotInputs(inputs)

	readHooks := snapshotAssemblyHooks{afterInputRead: hooks.afterInputRead}
	for _, input := range inputs {
		input.raw, err = readStableSnapshotInput(input, readHooks)
		if err != nil {
			return fmt.Errorf("read %s %q: %w", input.role, input.path, err)
		}
		if inputIsSignature(input.role) {
			input.digest = sha256.Sum256(input.raw)
		}
	}
	channelSignatures, releaseSignatures, err := sortedSnapshotSignatures(inputs)
	if err != nil {
		return err
	}
	rootUpdates, err := sortedSnapshotRootUpdates(inputs)
	if err != nil {
		return err
	}
	channelManifest := findSnapshotInput(inputs, "channel manifest")
	releaseManifest := findSnapshotInput(inputs, "release manifest")
	if channelManifest == nil || releaseManifest == nil {
		return errors.New("internal online bundle input classification failure")
	}
	bundleRaw, err := onlinerelease.Encode(onlinerelease.Bundle{
		RootUpdates:       snapshotInputBytes(rootUpdates),
		ChannelManifest:   channelManifest.raw,
		ChannelSignatures: snapshotSignatureBytes(channelSignatures),
		ReleaseManifest:   releaseManifest.raw,
		ReleaseSignatures: snapshotSignatureBytes(releaseSignatures),
	})
	if err != nil {
		return fmt.Errorf("encode online release bundle: %w", err)
	}
	if err := validateAllSnapshotInputs(inputs); err != nil {
		return err
	}
	if hooks.beforePublish != nil {
		hooks.beforePublish()
	}
	if err := writeNewFile(options.outputPath, bundleRaw, onlineBundleOutputMode); err != nil {
		return fmt.Errorf("publish online release bundle: %w", err)
	}
	if err := validateOnlineBundleReadback(options.outputPath, bundleRaw); err != nil {
		return err
	}
	return nil
}

func snapshotInputBytes(inputs []*openedSnapshotInput) [][]byte {
	result := make([][]byte, len(inputs))
	for index, input := range inputs {
		result[index] = input.raw
	}
	return result
}

func snapshotSignatureBytes(inputs []*openedSnapshotInput) [][]byte {
	result := make([][]byte, len(inputs))
	for index, input := range inputs {
		result[index] = input.raw
	}
	return result
}

func validateOnlineBundleReadback(path string, want []byte) error {
	input, err := openSnapshotInput(snapshotInputSpec{
		role:  "published online release bundle",
		path:  path,
		limit: onlinerelease.MaxEncodedBundleSize,
	})
	if err != nil {
		return fmt.Errorf("open online release bundle readback: %w", err)
	}
	defer input.file.Close()
	if os.FileMode(input.identity.mode).Perm() != onlineBundleOutputMode || input.identity.ownerUID != uint32(os.Geteuid()) {
		return errors.New("published online release bundle mode or owner changed unexpectedly")
	}
	got, err := readStableSnapshotInput(input, snapshotAssemblyHooks{})
	if err != nil {
		return fmt.Errorf("read online release bundle back: %w", err)
	}
	if !bytes.Equal(got, want) {
		return errors.New("published online release bundle readback changed exact bytes")
	}
	if _, err := onlinerelease.Parse(got); err != nil {
		return fmt.Errorf("parse published online release bundle readback: %w", err)
	}
	return nil
}
