package windowsinstall

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"

	releasetrust "mesh/internal/release"
	"mesh/internal/windowsbundle"
)

const (
	WindowsInstallSnapshotSchema     = "mesh-windows-install-snapshot-v1"
	WindowsInstallSnapshotFile       = "install.json"
	WindowsInstallSnapshotBundleFile = "bundle.json"
	WindowsInstallSnapshotArtifact   = "mesh-windows-bundle.tar"

	maximumWindowsInstallSnapshotDescriptorSize = 4096
	windowsOfflineArtifactCopyBufferSize        = 128 << 10
)

// WindowsInstallSnapshotDescriptor is an unsigned fixed-name locator. It has
// no policy, platform, clock, floor, size, digest, URL, or key input.
type WindowsInstallSnapshotDescriptor struct {
	Schema       string `json:"schema"`
	OnlineBundle string `json:"online_bundle"`
	Artifact     string `json:"artifact"`
}

func EncodeWindowsInstallSnapshotDescriptor(descriptor WindowsInstallSnapshotDescriptor) ([]byte, error) {
	if descriptor.Schema != WindowsInstallSnapshotSchema || descriptor.OnlineBundle != WindowsInstallSnapshotBundleFile || descriptor.Artifact != WindowsInstallSnapshotArtifact {
		return nil, errors.New("Windows install snapshot descriptor must use the exact schema and fixed basenames")
	}
	raw, err := json.Marshal(descriptor)
	if err != nil {
		return nil, fmt.Errorf("encode Windows install snapshot descriptor: %w", err)
	}
	raw = append(raw, '\n')
	if len(raw) > maximumWindowsInstallSnapshotDescriptorSize {
		return nil, errors.New("Windows install snapshot descriptor exceeds its size bound")
	}
	return raw, nil
}

func ParseWindowsInstallSnapshotDescriptor(raw []byte) (WindowsInstallSnapshotDescriptor, error) {
	if len(raw) == 0 || len(raw) > maximumWindowsInstallSnapshotDescriptorSize || !utf8.Valid(raw) {
		return WindowsInstallSnapshotDescriptor{}, errors.New("Windows install snapshot descriptor is empty, oversized, or invalid UTF-8")
	}
	if err := releasetrust.ValidateStrictJSON(raw); err != nil {
		return WindowsInstallSnapshotDescriptor{}, fmt.Errorf("Windows install snapshot descriptor JSON: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var descriptor WindowsInstallSnapshotDescriptor
	if err := decoder.Decode(&descriptor); err != nil {
		return WindowsInstallSnapshotDescriptor{}, fmt.Errorf("decode Windows install snapshot descriptor: %w", err)
	}
	if token, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err != nil {
			return WindowsInstallSnapshotDescriptor{}, fmt.Errorf("decode Windows install snapshot trailing data: %w", err)
		}
		return WindowsInstallSnapshotDescriptor{}, fmt.Errorf("decode Windows install snapshot trailing token %v", token)
	}
	canonical, err := EncodeWindowsInstallSnapshotDescriptor(descriptor)
	if err != nil {
		return WindowsInstallSnapshotDescriptor{}, err
	}
	if !bytes.Equal(raw, canonical) {
		return WindowsInstallSnapshotDescriptor{}, errors.New("Windows install snapshot descriptor is not canonical")
	}
	return descriptor, nil
}

func copyExactWindowsOfflineArtifact(ctx context.Context, source io.Reader, destination io.Writer, expected releasetrust.Artifact) error {
	if ctx == nil || source == nil || destination == nil {
		return errors.New("Windows offline artifact copy requires a context, source, and destination")
	}
	if err := releasetrust.ValidateArtifactReference(expected); err != nil || expected.OS != "windows" || expected.Size > windowsbundle.MaxArchiveSize {
		return errors.Join(err, errors.New("Windows offline artifact reference is invalid"))
	}
	wantDigest, err := hex.DecodeString(expected.SHA256)
	if err != nil || len(wantDigest) != sha256.Size {
		return errors.New("Windows offline artifact digest is invalid")
	}
	hasher := sha256.New()
	buffer := make([]byte, windowsOfflineArtifactCopyBufferSize)
	var copied int64
	sourceAtEOF := false
	for copied < expected.Size {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("copy Windows offline artifact: %w", err)
		}
		remaining := expected.Size - copied
		chunk := buffer
		if int64(len(chunk)) > remaining {
			chunk = chunk[:remaining]
		}
		read, readErr := source.Read(chunk)
		if read > 0 {
			written, writeErr := destination.Write(chunk[:read])
			if writeErr != nil || written != read {
				return errors.Join(writeErr, fmt.Errorf("Windows offline artifact short write: wrote %d of %d bytes", written, read))
			}
			_, _ = hasher.Write(chunk[:read])
			copied += int64(read)
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				if copied != expected.Size {
					return fmt.Errorf("Windows offline artifact was truncated at %d of %d bytes", copied, expected.Size)
				}
				sourceAtEOF = true
				break
			}
			return fmt.Errorf("read Windows offline artifact: %w", readErr)
		}
		if read == 0 {
			return io.ErrNoProgress
		}
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("copy Windows offline artifact: %w", err)
	}
	if !sourceAtEOF {
		var trailing [1]byte
		read, readErr := source.Read(trailing[:])
		if read > 0 {
			return errors.New("Windows offline artifact has data beyond its authenticated size")
		}
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return fmt.Errorf("check Windows offline artifact boundary: %w", readErr)
		}
		if readErr == nil {
			return io.ErrNoProgress
		}
	}
	if subtle.ConstantTimeCompare(hasher.Sum(nil), wantDigest) != 1 {
		return errors.New("Windows offline artifact SHA-256 differs from the threshold-authenticated release")
	}
	return nil
}
