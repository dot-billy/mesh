package backup

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"time"
)

const ManifestSchema = "mesh-backup-manifest-v1"

var (
	fixedEntryNames           = [...]string{"state.json", "identity-state.json", "master.key", "admin.token"}
	fixedExternalRequirements = [...]string{
		"backup-key-custody",
		"identity-policy-and-public-url",
		"oidc-client-secret-if-configured",
		"tls-or-trusted-proxy-configuration",
		"service-definition-and-trusted-binaries",
		"external-monotonic-backup-catalog",
	}
	schemaNamePattern  = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)
	lowerDigestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
	lowerIDPattern     = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

// FixedExternalRequirements returns the ordered requirements deliberately not
// contained in the encrypted archive. The returned slice is always detached.
func FixedExternalRequirements() []string {
	return append([]string(nil), fixedExternalRequirements[:]...)
}

type Entry struct {
	Name   string `json:"name"`
	Mode   string `json:"mode"`
	Size   uint64 `json:"size"`
	SHA256 string `json:"sha256"`
}

type Manifest struct {
	Schema               string   `json:"schema"`
	BackupID             string   `json:"backup_id"`
	CapturedAt           string   `json:"captured_at"`
	ControlVersion       uint64   `json:"control_version"`
	IdentitySchema       string   `json:"identity_schema"`
	ExternalRequirements []string `json:"external_requirements"`
	Entries              []Entry  `json:"entries"`
}

func (c *Codec) newManifest(source Source) (Manifest, error) {
	idBytes := make([]byte, 16)
	if _, err := io.ReadFull(c.random, idBytes); err != nil {
		return Manifest{}, fmt.Errorf("generate backup ID: %w", err)
	}
	backupID := hex.EncodeToString(idBytes)
	clear(idBytes)
	capturedAt := c.now().UTC().Truncate(time.Second).Format(time.RFC3339)

	masterBody := make([]byte, base64.RawURLEncoding.EncodedLen(len(source.MasterKey))+1)
	base64.RawURLEncoding.Encode(masterBody[:len(masterBody)-1], source.MasterKey)
	masterBody[len(masterBody)-1] = '\n'
	adminBody := make([]byte, len(source.AdminToken)+1)
	copy(adminBody, source.AdminToken)
	adminBody[len(adminBody)-1] = '\n'
	defer clear(masterBody)
	defer clear(adminBody)

	bodies := [][]byte{source.StateJSON, source.IdentityStateJSON, masterBody, adminBody}
	entries := make([]Entry, len(fixedEntryNames))
	for index, name := range fixedEntryNames {
		digest := sha256.Sum256(bodies[index])
		entries[index] = Entry{Name: name, Mode: "0600", Size: uint64(len(bodies[index])), SHA256: hex.EncodeToString(digest[:])}
	}
	manifest := Manifest{
		Schema: ManifestSchema, BackupID: backupID, CapturedAt: capturedAt,
		ControlVersion: source.ControlVersion, IdentitySchema: source.IdentitySchema,
		ExternalRequirements: FixedExternalRequirements(), Entries: entries,
	}
	if err := validateManifest(manifest); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func encodeManifest(manifest Manifest) ([]byte, error) {
	if err := validateManifest(manifest); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(manifest)
	if err != nil {
		return nil, fmt.Errorf("encode backup manifest: %w", err)
	}
	if len(raw) > maxManifestSize {
		return nil, errors.New("backup manifest exceeds its size limit")
	}
	return raw, nil
}

func decodePlaintext(plaintext []byte) (Contents, error) {
	if len(plaintext) < manifestSizeSize {
		return Contents{}, errors.New("backup plaintext is truncated")
	}
	manifestLength := uint64(binary.BigEndian.Uint32(plaintext[:manifestSizeSize]))
	if manifestLength == 0 || manifestLength > maxManifestSize || manifestLength > uint64(len(plaintext)-manifestSizeSize) {
		return Contents{}, errors.New("backup plaintext declares an invalid manifest size")
	}
	manifestEnd := manifestSizeSize + int(manifestLength)
	manifest, err := decodeManifest(plaintext[manifestSizeSize:manifestEnd])
	if err != nil {
		return Contents{}, err
	}

	expected := uint64(manifestEnd)
	for _, entry := range manifest.Entries {
		if entry.Size > uint64(MaxArchiveSize) || expected > uint64(MaxArchiveSize)-entry.Size {
			return Contents{}, errors.New("backup entry sizes overflow the archive limit")
		}
		expected += entry.Size
	}
	if expected != uint64(len(plaintext)) {
		return Contents{}, errors.New("backup plaintext is truncated or contains trailing data")
	}

	bodies := make([][]byte, len(manifest.Entries))
	offset := manifestEnd
	for index, entry := range manifest.Entries {
		end := offset + int(entry.Size)
		body := plaintext[offset:end]
		digest := sha256.Sum256(body)
		if hex.EncodeToString(digest[:]) != entry.SHA256 {
			return Contents{}, fmt.Errorf("backup entry %q digest does not match", entry.Name)
		}
		bodies[index] = body
		offset = end
	}

	masterKey, err := decodeMasterKeyBody(bodies[2])
	if err != nil {
		return Contents{}, err
	}
	adminToken, err := decodeAdminTokenBody(bodies[3])
	if err != nil {
		clear(masterKey)
		return Contents{}, err
	}
	return Contents{
		Manifest:          cloneManifest(manifest),
		StateJSON:         bytes.Clone(bodies[0]),
		IdentityStateJSON: bytes.Clone(bodies[1]),
		MasterKey:         masterKey,
		AdminToken:        adminToken,
	}, nil
}

func decodeManifest(raw []byte) (Manifest, error) {
	if len(raw) == 0 || len(raw) > maxManifestSize {
		return Manifest{}, errors.New("backup manifest has an invalid size")
	}
	if err := rejectDuplicateJSONNames(raw); err != nil {
		return Manifest{}, fmt.Errorf("decode backup manifest: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var manifest Manifest
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, fmt.Errorf("decode backup manifest: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Manifest{}, errors.New("backup manifest contains trailing JSON data")
	}
	if err := validateManifest(manifest); err != nil {
		return Manifest{}, err
	}
	canonical, err := json.Marshal(manifest)
	if err != nil {
		return Manifest{}, fmt.Errorf("re-encode backup manifest: %w", err)
	}
	if !bytes.Equal(raw, canonical) {
		return Manifest{}, errors.New("backup manifest is not in canonical JSON encoding")
	}
	return cloneManifest(manifest), nil
}

func validateManifest(manifest Manifest) error {
	if manifest.Schema != ManifestSchema {
		return errors.New("backup manifest has an unsupported schema")
	}
	if !lowerIDPattern.MatchString(manifest.BackupID) {
		return errors.New("backup manifest has a non-canonical backup ID")
	}
	parsedTime, err := time.Parse(time.RFC3339, manifest.CapturedAt)
	if err != nil || parsedTime.Location() != time.UTC || parsedTime.Nanosecond() != 0 || parsedTime.Format(time.RFC3339) != manifest.CapturedAt {
		return errors.New("backup manifest has a non-canonical capture time")
	}
	if manifest.ControlVersion == 0 {
		return errors.New("backup manifest has an invalid control version")
	}
	if !validSchemaName(manifest.IdentitySchema) {
		return errors.New("backup manifest has an invalid identity schema")
	}
	if !slices.Equal(manifest.ExternalRequirements, fixedExternalRequirements[:]) {
		return errors.New("backup manifest has an invalid external requirements list")
	}
	if len(manifest.Entries) != len(fixedEntryNames) {
		return errors.New("backup manifest must contain exactly four entries")
	}
	for index, entry := range manifest.Entries {
		if entry.Name != fixedEntryNames[index] {
			return errors.New("backup manifest entries are not in the required order")
		}
		if entry.Mode != "0600" {
			return fmt.Errorf("backup entry %q has an invalid mode", entry.Name)
		}
		if !lowerDigestPattern.MatchString(entry.SHA256) {
			return fmt.Errorf("backup entry %q has a non-canonical digest", entry.Name)
		}
		switch index {
		case 0:
			if entry.Size < 1 || entry.Size > MaxControlStateSize {
				return errors.New("control state entry has an invalid size")
			}
		case 1:
			if entry.Size < 1 || entry.Size > MaxIdentityStateSize {
				return errors.New("identity state entry has an invalid size")
			}
		case 2:
			if entry.Size != 44 {
				return errors.New("master key entry has an invalid size")
			}
		case 3:
			if entry.Size < 33 || entry.Size > 4097 {
				return errors.New("admin token entry has an invalid size")
			}
		}
	}
	return nil
}

func decodeMasterKeyBody(body []byte) ([]byte, error) {
	if len(body) != 44 || body[len(body)-1] != '\n' {
		return nil, errors.New("master key entry is not in canonical encoding")
	}
	encoded := body[:len(body)-1]
	decoded := make([]byte, base64.RawURLEncoding.DecodedLen(len(encoded)))
	decodedLength, err := base64.RawURLEncoding.Decode(decoded, encoded)
	if err != nil {
		clear(decoded)
		return nil, errors.New("master key entry is not in canonical encoding")
	}
	decoded = decoded[:decodedLength]
	canonical := base64.RawURLEncoding.AppendEncode(nil, decoded)
	canonicalMatch := bytes.Equal(encoded, canonical)
	clear(canonical)
	if len(decoded) != RootKeySize || !canonicalMatch {
		clear(decoded)
		return nil, errors.New("master key entry is not in canonical encoding")
	}
	return decoded, nil
}

func decodeAdminTokenBody(body []byte) ([]byte, error) {
	if len(body) < 33 || len(body) > 4097 || body[len(body)-1] != '\n' {
		return nil, errors.New("admin token entry is not in canonical encoding")
	}
	token := bytes.Clone(body[:len(body)-1])
	if err := validateAdminToken(token); err != nil {
		clear(token)
		return nil, errors.New("admin token entry is not in canonical encoding")
	}
	return token, nil
}

func validSchemaName(value string) bool {
	return schemaNamePattern.MatchString(value)
}

func cloneManifest(manifest Manifest) Manifest {
	clone := manifest
	clone.ExternalRequirements = append([]string(nil), manifest.ExternalRequirements...)
	clone.Entries = append([]Entry(nil), manifest.Entries...)
	return clone
}
