package verifierbundle

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"mesh/internal/agentstate"
	"mesh/internal/installerinspect"
	releasetrust "mesh/internal/release"
)

// Inspection is a complete static description of one canonical verifier
// archive. InspectArchive authenticates neither this digest nor the archive's
// publisher; a production handoff must carry the digest independently.
type Inspection struct {
	Package           Package
	Size              int64
	SHA256            string
	PackageJSONSHA256 string
}

// InspectFile takes one stable, bounded, single-link snapshot and proves that
// it is the exact deterministic archive Build would emit. It never executes,
// extracts, installs, signs, or downloads the verifier.
func InspectFile(path string) (Inspection, error) {
	raw, err := snapshotRegularFile(path, MaxArchiveSize)
	if err != nil {
		return Inspection{}, fmt.Errorf("snapshot verifier archive: %w", err)
	}
	return InspectArchive(raw)
}

// InspectArchive validates the complete canonical USTAR byte representation,
// metadata, standalone verifier digest, platform build identity, and capability
// separation. Alternate tar encodings and trailing bytes are rejected.
func InspectArchive(raw []byte) (Inspection, error) {
	if len(raw) == 0 || int64(len(raw)) > MaxArchiveSize {
		return Inspection{}, fmt.Errorf("verifier archive size must be between 1 and %d bytes", MaxArchiveSize)
	}
	reader := tar.NewReader(bytes.NewReader(raw))
	packageHeader, err := reader.Next()
	if err != nil {
		return Inspection{}, fmt.Errorf("read package.json header: %w", err)
	}
	if err := validateMemberHeader(packageHeader, packageJSONPath, packageJSONMode, maxPackageJSONSize); err != nil {
		return Inspection{}, err
	}
	packageRaw, err := readExactMember(reader, packageHeader.Size, maxPackageJSONSize)
	if err != nil {
		return Inspection{}, fmt.Errorf("read package.json: %w", err)
	}
	verifierHeader, err := reader.Next()
	if err != nil {
		return Inspection{}, fmt.Errorf("read standalone verifier header: %w", err)
	}
	if verifierHeader == nil || !supportedVerifierPath(verifierHeader.Name) {
		return Inspection{}, errors.New("standalone verifier archive path is not canonical")
	}
	if err := validateMemberHeader(verifierHeader, verifierHeader.Name, verifierMode, maxVerifierSize); err != nil {
		return Inspection{}, err
	}
	verifierRaw, err := readExactMember(reader, verifierHeader.Size, maxVerifierSize)
	if err != nil {
		return Inspection{}, fmt.Errorf("read standalone verifier: %w", err)
	}
	if _, err := reader.Next(); !errors.Is(err, io.EOF) {
		if err == nil {
			return Inspection{}, errors.New("verifier archive contains more than two members")
		}
		return Inspection{}, fmt.Errorf("finish verifier archive: %w", err)
	}

	if err := releasetrust.ValidateStrictJSON(packageRaw); err != nil {
		return Inspection{}, fmt.Errorf("package.json is not strict JSON: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(packageRaw))
	decoder.DisallowUnknownFields()
	var metadata Package
	if err := decoder.Decode(&metadata); err != nil {
		return Inspection{}, fmt.Errorf("decode package.json: %w", err)
	}
	canonicalPackage, err := marshalPackage(metadata)
	if err != nil {
		return Inspection{}, err
	}
	if !bytes.Equal(packageRaw, canonicalPackage) {
		return Inspection{}, errors.New("package.json is not canonical compact JSON followed by one LF")
	}
	buildTime, err := validatePackage(metadata)
	if err != nil {
		return Inspection{}, err
	}
	if !packageHeader.ModTime.Equal(buildTime) || !verifierHeader.ModTime.Equal(buildTime) {
		return Inspection{}, errors.New("verifier archive member times differ from the canonical build time")
	}
	entry := metadata.Entries[0]
	verifierDigest := sha256.Sum256(verifierRaw)
	if entry.Size != int64(len(verifierRaw)) || entry.SHA256 != hex.EncodeToString(verifierDigest[:]) {
		return Inspection{}, errors.New("standalone verifier bytes differ from package.json")
	}
	inspection, err := installerinspect.InspectVerifier(verifierRaw, metadata.Target.OS, metadata.Target.Arch)
	if err != nil {
		return Inspection{}, fmt.Errorf("inspect standalone verifier: %w", err)
	}
	identity := inspection.Identity
	if identity != metadata.Build {
		return Inspection{}, errors.New("standalone verifier compiled identity differs from package.json")
	}
	if identity.AgentStateReadMin > agentstate.CurrentSchemaVersion || identity.AgentStateReadMax < agentstate.CurrentSchemaVersion || identity.AgentStateWriteVersion != agentstate.CurrentWriteVersion {
		return Inspection{}, errors.New("standalone verifier does not carry the current canonical Mesh build compatibility identity")
	}
	if inspection.GoVersion != metadata.GoVersion {
		return Inspection{}, errors.New("standalone verifier Go version differs from package.json")
	}

	expectedSize, err := exactArchiveSize(int64(len(packageRaw)), int64(len(verifierRaw)))
	if err != nil {
		return Inspection{}, err
	}
	if int64(len(raw)) != expectedSize {
		return Inspection{}, fmt.Errorf("verifier archive size is %d, want %d", len(raw), expectedSize)
	}
	var rebuilt bytes.Buffer
	writer := tar.NewWriter(&rebuilt)
	if err := writeMember(writer, packageJSONPath, packageJSONMode, packageRaw, buildTime); err != nil {
		return Inspection{}, err
	}
	if err := writeMember(writer, entry.Path, verifierMode, verifierRaw, buildTime); err != nil {
		return Inspection{}, err
	}
	if err := writer.Close(); err != nil {
		return Inspection{}, fmt.Errorf("rebuild canonical verifier archive: %w", err)
	}
	if !bytes.Equal(raw, rebuilt.Bytes()) {
		return Inspection{}, errors.New("verifier archive is not the exact canonical USTAR representation")
	}
	archiveDigest := sha256.Sum256(raw)
	packageDigest := sha256.Sum256(packageRaw)
	return Inspection{
		Package: clonePackage(metadata), Size: int64(len(raw)),
		SHA256:            hex.EncodeToString(archiveDigest[:]),
		PackageJSONSHA256: hex.EncodeToString(packageDigest[:]),
	}, nil
}

func validateMemberHeader(header *tar.Header, name string, mode uint32, maximumSize int64) error {
	if header == nil || header.Name != name || header.Typeflag != tar.TypeReg || header.Format != tar.FormatUSTAR ||
		header.Mode != int64(mode) || header.Uid != 0 || header.Gid != 0 || header.Size <= 0 || header.Size > maximumSize ||
		header.ModTime.IsZero() || !header.AccessTime.IsZero() || !header.ChangeTime.IsZero() {
		return fmt.Errorf("verifier archive member %q has a noncanonical header", name)
	}
	return nil
}

func readExactMember(reader io.Reader, size, maximum int64) ([]byte, error) {
	if size <= 0 || size > maximum {
		return nil, errors.New("member size is outside its supported bound")
	}
	raw, err := io.ReadAll(io.LimitReader(reader, size+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) != size {
		return nil, errors.New("member payload size differs from its header")
	}
	return raw, nil
}
