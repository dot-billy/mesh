// Package onlinerelease implements the untrusted online transport wrapped
// around Mesh's existing threshold-authenticated release bytes.
package onlinerelease

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	releasetrust "mesh/internal/release"
)

const (
	SchemaV1             = "mesh-online-release-bundle-v1"
	SchemaV2             = "mesh-online-release-bundle-v2"
	Schema               = SchemaV2
	MaxEncodedBundleSize = 40 << 20
)

// Bundle contains exact manifest and detached-signature bytes. It deliberately
// carries no locator, key, policy, platform, clock, or security-floor input.
type Bundle struct {
	RootUpdates       [][]byte
	ChannelManifest   []byte
	ChannelSignatures [][]byte
	ReleaseManifest   []byte
	ReleaseSignatures [][]byte
}

type encodedBundleV1 struct {
	Schema            string   `json:"schema"`
	ChannelManifest   string   `json:"channel_manifest"`
	ChannelSignatures []string `json:"channel_signatures"`
	ReleaseManifest   string   `json:"release_manifest"`
	ReleaseSignatures []string `json:"release_signatures"`
}

type encodedBundleV2 struct {
	Schema            string   `json:"schema"`
	RootUpdates       []string `json:"root_updates"`
	ChannelManifest   string   `json:"channel_manifest"`
	ChannelSignatures []string `json:"channel_signatures"`
	ReleaseManifest   string   `json:"release_manifest"`
	ReleaseSignatures []string `json:"release_signatures"`
}

type encodedBundle = encodedBundleV2

// Encode emits the sole canonical transport representation: compact JSON in
// struct field order followed by exactly one LF byte.
func Encode(bundle Bundle) ([]byte, error) {
	return encodeForSchema(bundle, SchemaV2)
}

func encodeForSchema(bundle Bundle, schema string) ([]byte, error) {
	if err := validateBundle(bundle); err != nil {
		return nil, err
	}
	var document any
	switch schema {
	case SchemaV1:
		if bundle.RootUpdates != nil {
			return nil, errors.New("v1 online release bundle cannot carry root updates")
		}
		document = encodedBundleV1{
			Schema: schema, ChannelManifest: base64.RawURLEncoding.EncodeToString(bundle.ChannelManifest),
			ChannelSignatures: encodeByteSet(bundle.ChannelSignatures), ReleaseManifest: base64.RawURLEncoding.EncodeToString(bundle.ReleaseManifest),
			ReleaseSignatures: encodeByteSet(bundle.ReleaseSignatures),
		}
	case SchemaV2:
		rootUpdates := bundle.RootUpdates
		if rootUpdates == nil {
			rootUpdates = [][]byte{}
		}
		document = encodedBundleV2{
			Schema: schema, RootUpdates: encodeByteSet(rootUpdates), ChannelManifest: base64.RawURLEncoding.EncodeToString(bundle.ChannelManifest),
			ChannelSignatures: encodeByteSet(bundle.ChannelSignatures), ReleaseManifest: base64.RawURLEncoding.EncodeToString(bundle.ReleaseManifest),
			ReleaseSignatures: encodeByteSet(bundle.ReleaseSignatures),
		}
	default:
		return nil, fmt.Errorf("unsupported online release bundle schema %q", schema)
	}
	raw, err := json.Marshal(document)
	if err != nil {
		return nil, fmt.Errorf("encode online release bundle: %w", err)
	}
	raw = append(raw, '\n')
	if len(raw) > MaxEncodedBundleSize {
		return nil, fmt.Errorf("online release bundle exceeds %d bytes", MaxEncodedBundleSize)
	}
	return raw, nil
}

// Parse strictly decodes one canonical bundle and returns fresh ownership of
// every byte slice.
func Parse(raw []byte) (Bundle, error) {
	if len(raw) == 0 || len(raw) > MaxEncodedBundleSize {
		return Bundle{}, fmt.Errorf("online release bundle size must be between 1 and %d bytes", MaxEncodedBundleSize)
	}
	if err := releasetrust.ValidateStrictJSON(raw); err != nil {
		return Bundle{}, fmt.Errorf("invalid online release bundle JSON: %w", err)
	}
	var header struct {
		Schema string `json:"schema"`
	}
	if err := json.Unmarshal(raw, &header); err != nil {
		return Bundle{}, fmt.Errorf("decode online release bundle schema: %w", err)
	}
	var rootUpdates [][]byte
	var channelManifestText, releaseManifestText string
	var channelSignatureTexts, releaseSignatureTexts []string
	switch header.Schema {
	case SchemaV1:
		var document encodedBundleV1
		if err := decodeBundleDocument(raw, &document); err != nil {
			return Bundle{}, err
		}
		channelManifestText, channelSignatureTexts = document.ChannelManifest, document.ChannelSignatures
		releaseManifestText, releaseSignatureTexts = document.ReleaseManifest, document.ReleaseSignatures
	case SchemaV2:
		var document encodedBundleV2
		if err := decodeBundleDocument(raw, &document); err != nil {
			return Bundle{}, err
		}
		if document.RootUpdates == nil {
			return Bundle{}, errors.New("v2 online release bundle requires root_updates, which may be an empty array")
		}
		var err error
		rootUpdates, err = decodeRootUpdates(document.RootUpdates)
		if err != nil {
			return Bundle{}, err
		}
		if rootUpdates == nil {
			rootUpdates = [][]byte{}
		}
		channelManifestText, channelSignatureTexts = document.ChannelManifest, document.ChannelSignatures
		releaseManifestText, releaseSignatureTexts = document.ReleaseManifest, document.ReleaseSignatures
	default:
		return Bundle{}, fmt.Errorf("unsupported online release bundle schema %q", header.Schema)
	}
	channelManifest, err := decodeBytes(channelManifestText, "channel manifest", releasetrust.MaxManifestSize)
	if err != nil {
		return Bundle{}, err
	}
	channelSignatures, err := decodeByteSet(channelSignatureTexts, "channel signature", releasetrust.MaxEnvelopeSize)
	if err != nil {
		return Bundle{}, err
	}
	releaseManifest, err := decodeBytes(releaseManifestText, "release manifest", releasetrust.MaxManifestSize)
	if err != nil {
		return Bundle{}, err
	}
	releaseSignatures, err := decodeByteSet(releaseSignatureTexts, "release signature", releasetrust.MaxEnvelopeSize)
	if err != nil {
		return Bundle{}, err
	}
	bundle := Bundle{
		RootUpdates:     rootUpdates,
		ChannelManifest: channelManifest, ChannelSignatures: channelSignatures,
		ReleaseManifest: releaseManifest, ReleaseSignatures: releaseSignatures,
	}
	if err := validateBundle(bundle); err != nil {
		return Bundle{}, err
	}
	canonical, err := encodeForSchema(bundle, header.Schema)
	if err != nil {
		return Bundle{}, err
	}
	if !bytes.Equal(raw, canonical) {
		return Bundle{}, errors.New("online release bundle must use canonical compact JSON followed by one LF")
	}
	return cloneBundle(bundle), nil
}

func decodeBundleDocument(raw []byte, output any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return fmt.Errorf("decode online release bundle: %w", err)
	}
	return nil
}

func decodeRootUpdates(values []string) ([][]byte, error) {
	if len(values) > releasetrust.MaxRootUpdatesPerInput {
		return nil, fmt.Errorf("root update count must not exceed %d", releasetrust.MaxRootUpdatesPerInput)
	}
	decoded := make([][]byte, len(values))
	for index, value := range values {
		raw, err := decodeBytes(value, fmt.Sprintf("root update %d", index), releasetrust.MaxRootUpdateSize)
		if err != nil {
			return nil, err
		}
		decoded[index] = raw
	}
	return decoded, nil
}

func encodeByteSet(values [][]byte) []string {
	encoded := make([]string, len(values))
	for index, value := range values {
		encoded[index] = base64.RawURLEncoding.EncodeToString(value)
	}
	return encoded
}

func decodeByteSet(values []string, role string, maximum int) ([][]byte, error) {
	if len(values) == 0 || len(values) > releasetrust.MaxSignatureEnvelopes {
		return nil, fmt.Errorf("%s count must be between 1 and %d", role, releasetrust.MaxSignatureEnvelopes)
	}
	decoded := make([][]byte, len(values))
	for index, value := range values {
		raw, err := decodeBytes(value, fmt.Sprintf("%s %d", role, index), maximum)
		if err != nil {
			return nil, err
		}
		decoded[index] = raw
	}
	return decoded, nil
}

func decodeBytes(value, role string, maximum int) ([]byte, error) {
	if value == "" {
		return nil, fmt.Errorf("%s is empty", role)
	}
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || base64.RawURLEncoding.EncodeToString(raw) != value {
		return nil, fmt.Errorf("%s must be canonical unpadded base64url", role)
	}
	if len(raw) == 0 || len(raw) > maximum {
		return nil, fmt.Errorf("%s size must be between 1 and %d bytes", role, maximum)
	}
	return raw, nil
}

func validateBundle(bundle Bundle) error {
	if len(bundle.RootUpdates) > releasetrust.MaxRootUpdatesPerInput {
		return fmt.Errorf("root update count must not exceed %d", releasetrust.MaxRootUpdatesPerInput)
	}
	var previousRootVersion uint64
	for index, raw := range bundle.RootUpdates {
		if len(raw) == 0 || len(raw) > releasetrust.MaxRootUpdateSize {
			return fmt.Errorf("root update %d size must be between 1 and %d bytes", index, releasetrust.MaxRootUpdateSize)
		}
		update, err := releasetrust.ParseRootUpdate(raw)
		if err != nil {
			return fmt.Errorf("root update %d: %w", index, err)
		}
		root, err := releasetrust.ParseRoot(update.RootManifest)
		if err != nil {
			return fmt.Errorf("root update %d manifest: %w", index, err)
		}
		if index > 0 {
			if root.Document.Version == previousRootVersion {
				return fmt.Errorf("duplicate root update version %d", root.Document.Version)
			}
			if previousRootVersion == ^uint64(0) || root.Document.Version != previousRootVersion+1 {
				return fmt.Errorf("root update version %d does not continue version %d", root.Document.Version, previousRootVersion)
			}
		}
		previousRootVersion = root.Document.Version
	}
	if len(bundle.ChannelManifest) == 0 || len(bundle.ChannelManifest) > releasetrust.MaxManifestSize {
		return fmt.Errorf("channel manifest size must be between 1 and %d bytes", releasetrust.MaxManifestSize)
	}
	if len(bundle.ReleaseManifest) == 0 || len(bundle.ReleaseManifest) > releasetrust.MaxManifestSize {
		return fmt.Errorf("release manifest size must be between 1 and %d bytes", releasetrust.MaxManifestSize)
	}
	sets := []struct {
		role   string
		values [][]byte
	}{
		{role: "channel signature", values: bundle.ChannelSignatures},
		{role: "release signature", values: bundle.ReleaseSignatures},
	}
	seen := make(map[[sha256.Size]byte][][]byte)
	for _, set := range sets {
		if len(set.values) == 0 || len(set.values) > releasetrust.MaxSignatureEnvelopes {
			return fmt.Errorf("%s count must be between 1 and %d", set.role, releasetrust.MaxSignatureEnvelopes)
		}
		for index, value := range set.values {
			if len(value) == 0 || len(value) > releasetrust.MaxEnvelopeSize {
				return fmt.Errorf("%s %d size must be between 1 and %d bytes", set.role, index, releasetrust.MaxEnvelopeSize)
			}
			digest := sha256.Sum256(value)
			for _, previous := range seen[digest] {
				if bytes.Equal(previous, value) {
					return fmt.Errorf("%s %d is byte-identical to another signature envelope", set.role, index)
				}
			}
			seen[digest] = append(seen[digest], value)
		}
	}
	return nil
}

func cloneBundle(source Bundle) Bundle {
	cloneSet := func(values [][]byte) [][]byte {
		if values == nil {
			return nil
		}
		copy := make([][]byte, len(values))
		for index, value := range values {
			copy[index] = append([]byte(nil), value...)
		}
		return copy
	}
	return Bundle{
		RootUpdates:     cloneSet(source.RootUpdates),
		ChannelManifest: append([]byte(nil), source.ChannelManifest...), ChannelSignatures: cloneSet(source.ChannelSignatures),
		ReleaseManifest: append([]byte(nil), source.ReleaseManifest...), ReleaseSignatures: cloneSet(source.ReleaseSignatures),
	}
}
