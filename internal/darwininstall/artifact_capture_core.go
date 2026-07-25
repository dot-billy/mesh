package darwininstall

import (
	"errors"
	"fmt"
	"regexp"

	"mesh/internal/darwinbundle"
	releasetrust "mesh/internal/release"
)

var darwinArtifactCaptureDigestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

func darwinArtifactCaptureName(digest string) (string, error) {
	if !darwinArtifactCaptureDigestPattern.MatchString(digest) {
		return "", fmt.Errorf("Darwin artifact capture digest is not canonical")
	}
	return "artifact-" + digest + ".tar", nil
}

func darwinArtifactCapturePendingName(digest string) (string, error) {
	name, err := darwinArtifactCaptureName(digest)
	if err != nil {
		return "", err
	}
	return "." + name + ".new", nil
}

func validateDarwinArtifactReference(expected releasetrust.Artifact) error {
	if err := releasetrust.ValidateArtifactReference(expected); err != nil {
		return fmt.Errorf("Darwin artifact reference: %w", err)
	}
	if expected.OS != "darwin" || expected.Arch != "amd64" && expected.Arch != "arm64" {
		return errors.New("Darwin artifact capture requires a darwin/amd64 or darwin/arm64 artifact")
	}
	if expected.Size < 1 || expected.Size > darwinbundle.MaxArchiveSize {
		return fmt.Errorf("Darwin artifact size must be between 1 and %d bytes", darwinbundle.MaxArchiveSize)
	}
	return nil
}
