package windowsinstall

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

func TestWindowsInstallSnapshotDescriptorIsExactAndCanonical(t *testing.T) {
	descriptor := WindowsInstallSnapshotDescriptor{
		Schema: WindowsInstallSnapshotSchema, OnlineBundle: WindowsInstallSnapshotBundleFile, Artifact: WindowsInstallSnapshotArtifact,
	}
	raw, err := EncodeWindowsInstallSnapshotDescriptor(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseWindowsInstallSnapshotDescriptor(raw)
	if err != nil || parsed != descriptor {
		t.Fatalf("parsed descriptor = %#v, %v", parsed, err)
	}
	for name, candidate := range map[string][]byte{
		"unknown field":           bytes.Replace(raw, []byte("}\n"), []byte(",\"extra\":true}\n"), 1),
		"noncanonical whitespace": append(bytes.TrimSuffix(raw, []byte("\n")), ' ', '\n'),
		"wrong artifact":          bytes.Replace(raw, []byte(WindowsInstallSnapshotArtifact), []byte("other.tar"), 1),
		"trailing data":           append(append([]byte(nil), raw...), 'x'),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseWindowsInstallSnapshotDescriptor(candidate); err == nil {
				t.Fatal("invalid descriptor was accepted")
			}
		})
	}
}

func TestCopyExactWindowsOfflineArtifact(t *testing.T) {
	content := bytes.Repeat([]byte("offline-windows-artifact"), 16384)
	digest := sha256.Sum256(content)
	expected := releasetrust.Artifact{
		OS: "windows", Arch: "amd64", URL: "https://releases.example.invalid/mesh.tar",
		Size: int64(len(content)), SHA256: hex.EncodeToString(digest[:]),
	}
	var destination bytes.Buffer
	if err := copyExactWindowsOfflineArtifact(context.Background(), bytes.NewReader(content), &destination, expected); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(destination.Bytes(), content) {
		t.Fatal("offline artifact copy changed bytes")
	}
	for name, source := range map[string][]byte{
		"truncated": content[:len(content)-1],
		"appended":  append(append([]byte(nil), content...), 0),
		"drifted":   append([]byte{content[0] ^ 1}, content[1:]...),
	} {
		t.Run(name, func(t *testing.T) {
			if err := copyExactWindowsOfflineArtifact(context.Background(), bytes.NewReader(source), &bytes.Buffer{}, expected); err == nil {
				t.Fatal("invalid offline artifact copy succeeded")
			}
		})
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := copyExactWindowsOfflineArtifact(canceled, bytes.NewReader(content), &bytes.Buffer{}, expected); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled copy returned %v", err)
	}
	if err := copyExactWindowsOfflineArtifact(context.Background(), bytes.NewReader(content), windowsOfflineErrorWriter{}, expected); err == nil || !strings.Contains(err.Error(), "write") {
		t.Fatalf("failed writer returned %v", err)
	}
	if err := copyExactWindowsOfflineArtifact(context.Background(), &windowsDataAndEOFReader{content: content}, &bytes.Buffer{}, expected); err != nil {
		t.Fatalf("reader returning final data with EOF: %v", err)
	}
}

type windowsOfflineErrorWriter struct{}

func (windowsOfflineErrorWriter) Write([]byte) (int, error) {
	return 0, errors.New("injected write failure")
}

type windowsDataAndEOFReader struct {
	content []byte
	offset  int
}

func (reader *windowsDataAndEOFReader) Read(destination []byte) (int, error) {
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
