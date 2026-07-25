package release

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

// ValidateArtifactReference validates the complete signed locator and digest
// tuple before any network operation uses it. It deliberately does not select
// a platform or grant trust to the reference.
func ValidateArtifactReference(artifact Artifact) error {
	if !platformPattern.MatchString(artifact.OS) || !platformPattern.MatchString(artifact.Arch) {
		return fmt.Errorf("has invalid platform")
	}
	if artifact.Size <= 0 || artifact.Size > MaxArtifactSize {
		return fmt.Errorf("size must be between 1 and %d bytes", MaxArtifactSize)
	}
	if err := validateSHA256(artifact.SHA256); err != nil {
		return fmt.Errorf("sha256: %w", err)
	}
	if err := validateHTTPSURL(artifact.URL); err != nil {
		return fmt.Errorf("URL: %w", err)
	}
	return nil
}

// VerifyArtifact streams at most the signed size plus one byte. It rejects
// both truncation and appended data before comparing the signed SHA-256.
func VerifyArtifact(reader io.Reader, artifact Artifact) error {
	if artifact.Size <= 0 || artifact.Size > MaxArtifactSize {
		return fmt.Errorf("artifact size must be between 1 and %d bytes", MaxArtifactSize)
	}
	expected, err := hex.DecodeString(artifact.SHA256)
	if err != nil || len(expected) != sha256.Size || hex.EncodeToString(expected) != artifact.SHA256 {
		return fmt.Errorf("artifact SHA-256 is not canonical")
	}
	hasher := sha256.New()
	written, err := io.Copy(hasher, io.LimitReader(reader, artifact.Size+1))
	if err != nil {
		return fmt.Errorf("read artifact: %w", err)
	}
	if written != artifact.Size {
		return fmt.Errorf("artifact size is %d bytes; signed size is %d", written, artifact.Size)
	}
	if subtle.ConstantTimeCompare(hasher.Sum(nil), expected) != 1 {
		return fmt.Errorf("artifact SHA-256 does not match signed manifest")
	}
	return nil
}

func VerifyArtifactFile(path string, artifact Artifact) error {
	before, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return fmt.Errorf("artifact must be a regular file, not a symlink")
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) {
		return fmt.Errorf("artifact changed while opening")
	}
	if after.Size() != artifact.Size {
		return fmt.Errorf("artifact size is %d bytes; signed size is %d", after.Size(), artifact.Size)
	}
	return VerifyArtifact(file, artifact)
}
