package darwininstall

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"testing"

	releasetrust "mesh/internal/release"
)

func TestDarwinInstallSnapshotDescriptorIsExactAndCanonical(t *testing.T) {
	descriptor := DarwinInstallSnapshotDescriptor{
		Schema: DarwinInstallSnapshotSchema, OnlineBundle: DarwinInstallSnapshotBundleFile, Artifact: DarwinInstallSnapshotArtifact,
	}
	raw, err := EncodeDarwinInstallSnapshotDescriptor(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseDarwinInstallSnapshotDescriptor(raw)
	if err != nil || parsed != descriptor {
		t.Fatalf("parsed descriptor = %#v, %v", parsed, err)
	}
	for name, candidate := range map[string][]byte{
		"unknown field":           bytes.Replace(raw, []byte("\n"), []byte(",\"extra\":true}\n"), 1),
		"noncanonical whitespace": append(bytes.TrimSuffix(raw, []byte("\n")), ' ', '\n'),
		"wrong artifact":          bytes.Replace(raw, []byte(DarwinInstallSnapshotArtifact), []byte("other.tar"), 1),
		"trailing data":           append(append([]byte(nil), raw...), 'x'),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseDarwinInstallSnapshotDescriptor(candidate); err == nil {
				t.Fatal("invalid descriptor was accepted")
			}
		})
	}
}

func TestCopyExactDarwinOfflineArtifact(t *testing.T) {
	content := bytes.Repeat([]byte("offline-darwin-artifact"), 16384)
	digest := sha256.Sum256(content)
	expected := releasetrust.Artifact{
		OS: "darwin", Arch: "arm64", URL: "https://releases.example.invalid/mesh.tar",
		Size: int64(len(content)), SHA256: hex.EncodeToString(digest[:]),
	}
	var destination bytes.Buffer
	if err := copyExactDarwinOfflineArtifact(context.Background(), bytes.NewReader(content), &destination, expected); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(destination.Bytes(), content) {
		t.Fatal("offline artifact copy changed bytes")
	}
	destination.Reset()
	if err := copyExactDarwinOfflineArtifact(context.Background(), &dataAndEOFReader{content: content}, &destination, expected); err != nil {
		t.Fatalf("reader returning final data with EOF: %v", err)
	}
	for name, mutate := range map[string]func() ([]byte, releasetrust.Artifact){
		"truncated": func() ([]byte, releasetrust.Artifact) { return content[:len(content)-1], expected },
		"appended":  func() ([]byte, releasetrust.Artifact) { return append(append([]byte(nil), content...), 0), expected },
		"digest": func() ([]byte, releasetrust.Artifact) {
			changed := append([]byte(nil), content...)
			changed[0] ^= 1
			return changed, expected
		},
	} {
		t.Run(name, func(t *testing.T) {
			source, candidate := mutate()
			if err := copyExactDarwinOfflineArtifact(context.Background(), bytes.NewReader(source), &bytes.Buffer{}, candidate); err == nil {
				t.Fatal("invalid offline artifact copy succeeded")
			}
		})
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := copyExactDarwinOfflineArtifact(canceled, bytes.NewReader(content), &bytes.Buffer{}, expected); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled copy returned %v", err)
	}
	if err := copyExactDarwinOfflineArtifact(context.Background(), bytes.NewReader(content), errorWriter{}, expected); err == nil || !strings.Contains(err.Error(), "write") {
		t.Fatalf("failed writer returned %v", err)
	}
}

type errorWriter struct{}

func (errorWriter) Write([]byte) (int, error) { return 0, errors.New("injected write failure") }

type dataAndEOFReader struct {
	content []byte
	offset  int
}

func (reader *dataAndEOFReader) Read(destination []byte) (int, error) {
	if reader.offset == len(reader.content) {
		return 0, io.EOF
	}
	read := copy(destination, reader.content[reader.offset:])
	reader.offset += read
	if reader.offset == len(reader.content) {
		return read, io.EOF
	}
	return read, nil
}
