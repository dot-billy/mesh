package darwininstall

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
)

const (
	DarwinInstallSnapshotSchema     = "mesh-darwin-install-snapshot-v1"
	DarwinInstallSnapshotFile       = "install.json"
	DarwinInstallSnapshotBundleFile = "bundle.json"
	DarwinInstallSnapshotArtifact   = "mesh-darwin-bundle.tar"

	maximumDarwinInstallSnapshotDescriptorSize = 4096
	darwinOfflineArtifactCopyBufferSize        = 128 << 10
)

// DarwinInstallSnapshotDescriptor is an unsigned, fixed-name locator. It has
// no policy, platform, clock, floor, size, digest, or key field that could
// influence authentication.
type DarwinInstallSnapshotDescriptor struct {
	Schema       string `json:"schema"`
	OnlineBundle string `json:"online_bundle"`
	Artifact     string `json:"artifact"`
}

func EncodeDarwinInstallSnapshotDescriptor(descriptor DarwinInstallSnapshotDescriptor) ([]byte, error) {
	if descriptor.Schema != DarwinInstallSnapshotSchema || descriptor.OnlineBundle != DarwinInstallSnapshotBundleFile || descriptor.Artifact != DarwinInstallSnapshotArtifact {
		return nil, errors.New("Darwin install snapshot descriptor must use the exact schema and fixed basenames")
	}
	raw, err := json.Marshal(descriptor)
	if err != nil {
		return nil, fmt.Errorf("encode Darwin install snapshot descriptor: %w", err)
	}
	raw = append(raw, '\n')
	if len(raw) > maximumDarwinInstallSnapshotDescriptorSize {
		return nil, errors.New("Darwin install snapshot descriptor exceeds its size bound")
	}
	return raw, nil
}

func ParseDarwinInstallSnapshotDescriptor(raw []byte) (DarwinInstallSnapshotDescriptor, error) {
	if len(raw) == 0 || len(raw) > maximumDarwinInstallSnapshotDescriptorSize || !utf8.Valid(raw) {
		return DarwinInstallSnapshotDescriptor{}, errors.New("Darwin install snapshot descriptor is empty, oversized, or invalid UTF-8")
	}
	if err := releasetrust.ValidateStrictJSON(raw); err != nil {
		return DarwinInstallSnapshotDescriptor{}, fmt.Errorf("Darwin install snapshot descriptor JSON: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var descriptor DarwinInstallSnapshotDescriptor
	if err := decoder.Decode(&descriptor); err != nil {
		return DarwinInstallSnapshotDescriptor{}, fmt.Errorf("decode Darwin install snapshot descriptor: %w", err)
	}
	if token, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err != nil {
			return DarwinInstallSnapshotDescriptor{}, fmt.Errorf("decode Darwin install snapshot trailing data: %w", err)
		}
		return DarwinInstallSnapshotDescriptor{}, fmt.Errorf("decode Darwin install snapshot trailing token %v", token)
	}
	canonical, err := EncodeDarwinInstallSnapshotDescriptor(descriptor)
	if err != nil {
		return DarwinInstallSnapshotDescriptor{}, err
	}
	if !bytes.Equal(raw, canonical) {
		return DarwinInstallSnapshotDescriptor{}, errors.New("Darwin install snapshot descriptor is not canonical")
	}
	return descriptor, nil
}

// copyExactDarwinOfflineArtifact copies only the threshold-authenticated byte
// count, rejects both truncation and appended data, and independently verifies
// SHA-256 before the capture layer performs its own publication-time rehash.
func copyExactDarwinOfflineArtifact(ctx context.Context, source io.Reader, destination io.Writer, expected releasetrust.Artifact) error {
	if ctx == nil || source == nil || destination == nil {
		return errors.New("Darwin offline artifact copy requires a context, source, and destination")
	}
	if err := validateDarwinArtifactReference(expected); err != nil {
		return err
	}
	wantDigest, err := hex.DecodeString(expected.SHA256)
	if err != nil || len(wantDigest) != sha256.Size {
		return errors.New("Darwin offline artifact digest is invalid")
	}
	hasher := sha256.New()
	buffer := make([]byte, darwinOfflineArtifactCopyBufferSize)
	var copied int64
	sourceAtEOF := false
	for copied < expected.Size {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("copy Darwin offline artifact: %w", err)
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
				return errors.Join(writeErr, fmt.Errorf("Darwin offline artifact short write: wrote %d of %d bytes", written, read))
			}
			_, _ = hasher.Write(chunk[:read])
			copied += int64(read)
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				if copied != expected.Size {
					return fmt.Errorf("Darwin offline artifact was truncated at %d of %d bytes", copied, expected.Size)
				}
				sourceAtEOF = true
				break
			}
			return fmt.Errorf("read Darwin offline artifact: %w", readErr)
		}
		if read == 0 {
			return io.ErrNoProgress
		}
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("copy Darwin offline artifact: %w", err)
	}
	if !sourceAtEOF {
		var trailing [1]byte
		read, readErr := source.Read(trailing[:])
		if read > 0 {
			return errors.New("Darwin offline artifact has data beyond its authenticated size")
		}
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return fmt.Errorf("check Darwin offline artifact boundary: %w", readErr)
		}
		if readErr == nil {
			return io.ErrNoProgress
		}
	}
	if subtle.ConstantTimeCompare(hasher.Sum(nil), wantDigest) != 1 {
		return errors.New("Darwin offline artifact SHA-256 differs from the threshold-authenticated release")
	}
	return nil
}
