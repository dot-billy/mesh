// Package bootstrapanchorauthor creates the unsigned transfer file from one
// canonical handoff. It is separate from the narrow verification package.
package bootstrapanchorauthor

import (
	"crypto/sha256"
	"encoding/hex"

	"mesh/internal/bootstrapanchor"
	"mesh/internal/bootstraphandoff"
)

func Create(handoffRaw []byte) (bootstrapanchor.Document, []byte, error) {
	handoff, err := bootstraphandoff.Parse(handoffRaw)
	if err != nil {
		return bootstrapanchor.Document{}, nil, err
	}
	digest := sha256.Sum256(handoffRaw)
	verifiers := make([]bootstrapanchor.VerifierReference, len(handoff.Verifiers))
	for index, verifier := range handoff.Verifiers {
		verifiers[index] = bootstrapanchor.VerifierReference{
			Name: verifier.Name, OS: verifier.OS, Arch: verifier.Arch, SHA256: verifier.SHA256,
		}
	}
	anchorSchema := bootstrapanchor.Schema
	if handoff.Schema == bootstraphandoff.LegacySchema {
		anchorSchema = bootstrapanchor.LegacySchema
	}
	document := bootstrapanchor.Document{
		Schema: anchorSchema, Channel: handoff.Channel,
		Handoff: bootstrapanchor.HandoffReference{
			Name: bootstrapanchor.HandoffName, Size: int64(len(handoffRaw)),
			SHA256: hex.EncodeToString(digest[:]), IssuedAt: handoff.IssuedAt, ExpiresAt: handoff.ExpiresAt,
		},
		Root: bootstrapanchor.RootReference{
			Name: handoff.Root.Name, Version: handoff.Root.Version,
			ReleaseEpoch: handoff.Root.ReleaseEpoch, SHA256: handoff.Root.SHA256,
		},
		Build: bootstrapanchor.BuildReference{
			Version: handoff.Build.Version, Commit: handoff.Build.Commit, SecurityFloor: handoff.Build.SecurityFloor,
		},
		Verifiers: verifiers,
	}
	raw, err := bootstrapanchor.Encode(document)
	if err != nil {
		return bootstrapanchor.Document{}, nil, err
	}
	return document, raw, nil
}
