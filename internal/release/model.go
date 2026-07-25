// Package release implements the offline trust primitives used to authenticate
// Mesh release metadata and artifacts. It deliberately performs no network or
// installation operations.
package release

import "time"

const (
	ChannelSchema           = "mesh-channel-manifest-v1"
	ReleaseSchema           = "mesh-release-manifest-v1"
	ChannelSchemaV2         = "mesh-channel-manifest-v2"
	ReleaseSchemaV2         = "mesh-release-manifest-v2"
	SignatureEnvelopeSchema = "mesh-detached-signature-v1"
	PublicKeySchema         = "mesh-ed25519-public-key-v1"
	PrivateKeySchema        = "mesh-ed25519-private-key-v1" // gitleaks:allow -- schema identifier, not key material

	MaxManifestSize             = 1 << 20
	MaxEnvelopeSize             = 4 << 10
	MaxKeyFileSize              = 4 << 10
	MaxSignatureEnvelopes       = 256
	MaxTrustedKeys              = 64
	MaxArtifactSize       int64 = 16 << 30
	DefaultThreshold            = 2
)

type ManifestKind string

const (
	RootManifestKind      ManifestKind = "root"
	BootstrapManifestKind ManifestKind = "bootstrap"
	ChannelManifestKind   ManifestKind = "channel"
	ReleaseManifestKind   ManifestKind = "release"
)

// ChannelManifest is the small, frequently updated pointer for a release
// channel. Release binds the exact release manifest bytes, not a re-encoded
// representation.
type ChannelManifest struct {
	Schema               string           `json:"schema"`
	Channel              string           `json:"channel"`
	ReleaseEpoch         uint64           `json:"release_epoch,omitempty"`
	Sequence             uint64           `json:"sequence"`
	MinimumSecurityFloor uint64           `json:"minimum_security_floor"`
	IssuedAt             string           `json:"issued_at"`
	ExpiresAt            string           `json:"expires_at"`
	Release              ReleaseReference `json:"release"`
}

type ReleaseReference struct {
	Version        string `json:"version"`
	Sequence       uint64 `json:"sequence"`
	ManifestURL    string `json:"manifest_url"`
	ManifestSize   int64  `json:"manifest_size"`
	ManifestSHA256 string `json:"manifest_sha256"`
}

// ReleaseManifest binds version and replay metadata to one exact artifact for
// each supported platform.
type ReleaseManifest struct {
	Schema               string     `json:"schema"`
	Channel              string     `json:"channel"`
	ReleaseEpoch         uint64     `json:"release_epoch,omitempty"`
	Version              string     `json:"version"`
	Sequence             uint64     `json:"sequence"`
	MinimumSecurityFloor uint64     `json:"minimum_security_floor"`
	IssuedAt             string     `json:"issued_at"`
	ExpiresAt            string     `json:"expires_at"`
	Artifacts            []Artifact `json:"artifacts"`
}

type Artifact struct {
	OS     string `json:"os"`
	Arch   string `json:"arch"`
	URL    string `json:"url"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// SignatureEnvelope is intentionally one-signature-per-file so independent
// release key holders never need to share a writable envelope.
type SignatureEnvelope struct {
	Schema       string `json:"schema"`
	ManifestType string `json:"manifest_type"`
	KeyID        string `json:"key_id"`
	Signature    string `json:"signature"`
}

type PublicKeyFile struct {
	Schema    string `json:"schema"`
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"`
}

type PrivateKeyFile struct {
	Schema     string `json:"schema"`
	KeyID      string `json:"key_id"`
	PrivateKey string `json:"private_key"`
}

// VerificationPolicy carries state that cannot safely come from a signed
// manifest itself. MinimumSequence and MinimumSecurityFloor are expected to be
// persisted by an updater. SupportedSecurityFloor comes from the verifier
// build, and prevents a new manifest from silently opting an old verifier into
// semantics it does not implement.
type VerificationPolicy struct {
	Now                    time.Time
	ClockSkew              time.Duration
	Threshold              int
	MinimumSequence        uint64
	MinimumSecurityFloor   uint64
	SupportedSecurityFloor uint64
	ExpectedChannel        string
	ExpectedReleaseEpoch   uint64
	MinimumReleaseEpoch    uint64
	AllowLegacyEpochOne    bool
	PlatformOS             string
	PlatformArch           string
}

type ParsedManifest struct {
	Kind             ManifestKind
	ReleaseEpoch     uint64
	Channel          *ChannelManifest
	Release          *ReleaseManifest
	IssuedAt         time.Time
	ExpiresAt        time.Time
	SelectedArtifact *Artifact
}

type VerifiedManifest struct {
	ParsedManifest
	SignerKeyIDs []string
}
