// Package bootstraphandoffauthor builds the unsigned canonical handoff from
// already-inspected verifier archives. It is intentionally separate from the
// schema/resolution package used by the narrow standalone verifier.
package bootstraphandoffauthor

import (
	"errors"
	"fmt"
	"sort"
	"time"

	"mesh/internal/bootstraphandoff"
	releasetrust "mesh/internal/release"
	"mesh/internal/verifierbundle"
)

// Create binds already-inspected verifier packages to one exact canonical
// root. The resulting bytes acquire authority only when their SHA-256 is
// delivered through an independent operator channel.
func Create(rootRaw []byte, inspections []verifierbundle.Inspection, issuedText, expiresText string) (bootstraphandoff.Document, []byte, error) {
	if len(rootRaw) == 0 || len(rootRaw) > releasetrust.MaxRootSize {
		return bootstraphandoff.Document{}, nil, fmt.Errorf("bootstrap root size must be between 1 and %d bytes", releasetrust.MaxRootSize)
	}
	root, err := releasetrust.ParseRoot(rootRaw)
	if err != nil {
		return bootstraphandoff.Document{}, nil, fmt.Errorf("parse bootstrap root: %w", err)
	}
	if root.Document.Version != 1 || root.Document.ReleaseEpoch != 1 {
		return bootstraphandoff.Document{}, nil, errors.New("bootstrap handoff requires root version 1 and release epoch 1")
	}
	issuedAt, err := parseTime(issuedText, "issued_at")
	if err != nil {
		return bootstraphandoff.Document{}, nil, err
	}
	expiresAt, err := parseTime(expiresText, "expires_at")
	if err != nil {
		return bootstraphandoff.Document{}, nil, err
	}
	if err := releasetrust.ValidateCurrentRoot(root, issuedAt, 0); err != nil {
		return bootstraphandoff.Document{}, nil, fmt.Errorf("bootstrap root at handoff issuance: %w", err)
	}
	if issuedAt.Before(root.IssuedAt) || expiresAt.After(root.ExpiresAt) {
		return bootstraphandoff.Document{}, nil, errors.New("bootstrap handoff validity must stay within the version-1 root validity")
	}
	if len(inspections) != 4 {
		return bootstraphandoff.Document{}, nil, errors.New("bootstrap handoff requires exactly linux and windows verifier packages for amd64 and arm64")
	}
	sorted := append([]verifierbundle.Inspection(nil), inspections...)
	sort.Slice(sorted, func(left, right int) bool {
		if sorted[left].Package.Target.OS != sorted[right].Package.Target.OS {
			return sorted[left].Package.Target.OS < sorted[right].Package.Target.OS
		}
		return sorted[left].Package.Target.Arch < sorted[right].Package.Target.Arch
	})
	first := sorted[0]
	wantTargets := []verifierbundle.Target{{OS: "linux", Arch: "amd64"}, {OS: "linux", Arch: "arm64"}, {OS: "windows", Arch: "amd64"}, {OS: "windows", Arch: "arm64"}}
	for index, want := range wantTargets {
		if sorted[index].Package.Target != want {
			return bootstraphandoff.Document{}, nil, errors.New("bootstrap handoff requires exactly one verifier package for linux/amd64, linux/arm64, windows/amd64, and windows/arm64")
		}
	}
	for _, inspection := range sorted[1:] {
		if first.Package.Build != inspection.Package.Build || first.Package.GoVersion != inspection.Package.GoVersion {
			return bootstraphandoff.Document{}, nil, errors.New("bootstrap verifier packages must share one exact build identity and Go version")
		}
	}
	buildTime, err := time.Parse(time.RFC3339, first.Package.Build.BuildTime)
	if err != nil || buildTime.After(issuedAt) {
		return bootstraphandoff.Document{}, nil, errors.New("bootstrap verifier build time cannot follow handoff issuance")
	}
	if first.Package.Build.SecurityFloor < root.Document.MinimumSecurityFloor {
		return bootstraphandoff.Document{}, nil, errors.New("bootstrap verifier security floor is below the version-1 root floor")
	}
	verifiers := make([]bootstraphandoff.VerifierReference, 0, len(sorted))
	for _, inspection := range sorted {
		entry := inspection.Package.Entries[0]
		verifiers = append(verifiers, bootstraphandoff.VerifierReference{
			Name: bootstraphandoff.VerifierName(inspection.Package.Target.OS, inspection.Package.Target.Arch), OS: inspection.Package.Target.OS, Arch: inspection.Package.Target.Arch,
			Size: inspection.Size, SHA256: inspection.SHA256, PackageJSONSHA256: inspection.PackageJSONSHA256,
			VerifierSHA256: entry.SHA256,
		})
	}
	document := bootstraphandoff.Document{
		Schema: bootstraphandoff.Schema, Channel: root.Document.Channel, IssuedAt: issuedText, ExpiresAt: expiresText,
		Root: bootstraphandoff.RootReference{
			Name: bootstraphandoff.RootName, Version: 1, ReleaseEpoch: 1,
			MinimumSecurityFloor: root.Document.MinimumSecurityFloor,
			IssuedAt:             root.Document.IssuedAt, ExpiresAt: root.Document.ExpiresAt,
			Size: int64(len(rootRaw)), SHA256: root.SHA256,
		},
		Build: first.Package.Build, GoVersion: first.Package.GoVersion, Verifiers: verifiers,
	}
	raw, err := bootstraphandoff.Encode(document)
	if err != nil {
		return bootstraphandoff.Document{}, nil, err
	}
	return document, raw, nil
}

func parseTime(value, name string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil || parsed.UTC().Format(time.RFC3339) != value {
		return time.Time{}, fmt.Errorf("%s must be canonical UTC RFC3339 without fractional seconds", name)
	}
	return parsed.UTC(), nil
}
