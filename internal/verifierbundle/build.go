package verifierbundle

import (
	"archive/tar"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"mesh/internal/agentstate"
	"mesh/internal/buildinfo"
	"mesh/internal/installerinspect"
)

const tarBlockSize int64 = 512

// Build creates one deterministic uncompressed USTAR without replacing an
// existing output. It never executes, signs, downloads, or installs its input.
func Build(options BuildOptions) (BuildResult, error) {
	if runtime.GOOS != "linux" {
		return BuildResult{}, errors.New("bootstrap verifier bundle construction requires a Linux packaging host")
	}
	options.Version = strings.TrimSpace(options.Version)
	options.Commit = strings.TrimSpace(options.Commit)
	options.OS = strings.TrimSpace(options.OS)
	if options.OS == "" {
		options.OS = "linux"
	}
	options.Arch = strings.TrimSpace(options.Arch)
	if options.Version == "" || options.Commit == "" || options.SecurityFloor == 0 || !supportedOS(options.OS) || !supportedArch(options.Arch) {
		return BuildResult{}, errors.New("version, commit, positive security floor, and linux or windows target with amd64 or arm64 are required")
	}
	buildTimeText, err := canonicalEpoch(options.SourceDateEpoch)
	if err != nil {
		return BuildResult{}, err
	}
	content, err := snapshotRegularFile(options.VerifierPath, maxVerifierSize)
	if err != nil {
		return BuildResult{}, fmt.Errorf("snapshot standalone verifier: %w", err)
	}
	inspection, err := installerinspect.InspectVerifier(content, options.OS, options.Arch)
	if err != nil {
		return BuildResult{}, fmt.Errorf("inspect standalone verifier: %w", err)
	}
	identity := inspection.Identity
	if identity.Schema != buildinfo.Schema || identity.Version != options.Version || identity.Commit != options.Commit ||
		identity.BuildTime != buildTimeText || identity.SecurityFloor != options.SecurityFloor {
		return BuildResult{}, errors.New("standalone verifier compiled identity does not match requested package identity")
	}
	if identity.AgentStateReadMin > agentstate.CurrentSchemaVersion || identity.AgentStateReadMax < agentstate.CurrentSchemaVersion || identity.AgentStateWriteVersion != agentstate.CurrentWriteVersion {
		return BuildResult{}, errors.New("standalone verifier does not carry the current canonical Mesh build compatibility identity")
	}
	digest := sha256.Sum256(content)
	metadata := Package{
		Schema: Schema, Build: identity, GoVersion: inspection.GoVersion,
		Target:  Target{OS: options.OS, Arch: options.Arch},
		Entries: []Entry{{Path: verifierPath(options.OS), Mode: verifierMode, Size: int64(len(content)), SHA256: hex.EncodeToString(digest[:])}},
	}
	buildTime, err := validatePackage(metadata)
	if err != nil {
		return BuildResult{}, err
	}
	packageJSON, err := marshalPackage(metadata)
	if err != nil {
		return BuildResult{}, err
	}
	expectedSize, err := exactArchiveSize(int64(len(packageJSON)), int64(len(content)))
	if err != nil {
		return BuildResult{}, err
	}
	outputPath, parentPath, outputName, err := prepareOutputPath(options.OutputPath)
	if err != nil {
		return BuildResult{}, err
	}
	parentInfo, err := os.Lstat(parentPath)
	if err != nil || parentInfo.Mode()&os.ModeSymlink != 0 || !parentInfo.IsDir() {
		return BuildResult{}, errors.New("output parent must be an existing real directory")
	}
	resolvedParent, err := filepath.EvalSymlinks(parentPath)
	if err != nil || filepath.Clean(resolvedParent) != parentPath {
		return BuildResult{}, errors.New("output parent path cannot traverse symlinks")
	}
	parentDirectory, err := os.Open(parentPath)
	if err != nil {
		return BuildResult{}, fmt.Errorf("open output parent: %w", err)
	}
	defer parentDirectory.Close()
	openedParentInfo, err := parentDirectory.Stat()
	if err != nil || !os.SameFile(parentInfo, openedParentInfo) {
		return BuildResult{}, errors.New("output parent changed while opening")
	}
	root, err := os.OpenRoot(parentPath)
	if err != nil {
		return BuildResult{}, fmt.Errorf("anchor output parent: %w", err)
	}
	defer root.Close()
	rootInfo, err := root.Stat(".")
	if err != nil || !os.SameFile(openedParentInfo, rootInfo) {
		return BuildResult{}, errors.New("output parent changed while anchoring")
	}
	if _, err := root.Lstat(outputName); err == nil {
		return BuildResult{}, fmt.Errorf("output %q already exists", outputPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return BuildResult{}, fmt.Errorf("inspect output: %w", err)
	}
	temporaryName, err := randomName(".mesh-bootstrap-verifier-bundle-")
	if err != nil {
		return BuildResult{}, err
	}
	temporary, err := root.OpenFile(temporaryName, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return BuildResult{}, fmt.Errorf("create private bundle output: %w", err)
	}
	temporaryOwned := true
	defer func() {
		_ = temporary.Close()
		if temporaryOwned {
			_ = root.Remove(temporaryName)
		}
	}()
	hasher := sha256.New()
	writer := tar.NewWriter(io.MultiWriter(temporary, hasher))
	if err := writeMember(writer, packageJSONPath, packageJSONMode, packageJSON, buildTime); err != nil {
		return BuildResult{}, err
	}
	if err := writeMember(writer, verifierPath(options.OS), verifierMode, content, buildTime); err != nil {
		return BuildResult{}, err
	}
	if err := writer.Close(); err != nil {
		return BuildResult{}, fmt.Errorf("finish canonical USTAR: %w", err)
	}
	info, err := temporary.Stat()
	if err != nil || info.Size() != expectedSize || info.Size() > MaxArchiveSize {
		return BuildResult{}, fmt.Errorf("canonical verifier bundle size is invalid: got %d, want %d", fileSize(info), expectedSize)
	}
	if err := temporary.Chmod(0o644); err != nil {
		return BuildResult{}, fmt.Errorf("set published bundle mode: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return BuildResult{}, fmt.Errorf("sync completed bundle: %w", err)
	}
	if err := root.Link(temporaryName, outputName); err != nil {
		return BuildResult{}, fmt.Errorf("publish bundle without replacement: %w", err)
	}
	published := true
	cleanupPublished := func() {
		if published {
			_ = root.Remove(outputName)
			_ = parentDirectory.Sync()
		}
	}
	if err := parentDirectory.Sync(); err != nil {
		cleanupPublished()
		return BuildResult{}, fmt.Errorf("sync bundle publication: %w", err)
	}
	outputInfo, outputErr := root.Lstat(outputName)
	currentInfo, currentErr := temporary.Stat()
	if outputErr != nil || currentErr != nil || !exactRegularMode(outputInfo, 0o644) || !os.SameFile(outputInfo, currentInfo) {
		cleanupPublished()
		return BuildResult{}, errors.New("published bundle identity or mode changed")
	}
	if err := root.Remove(temporaryName); err != nil {
		cleanupPublished()
		return BuildResult{}, fmt.Errorf("remove private bundle staging name: %w", err)
	}
	temporaryOwned = false
	if err := parentDirectory.Sync(); err != nil {
		cleanupPublished()
		return BuildResult{}, fmt.Errorf("sync private bundle cleanup: %w", err)
	}
	finalInfo, err := root.Lstat(outputName)
	if err != nil || !exactRegularMode(finalInfo, 0o644) || finalInfo.Size() != expectedSize || !singleLink(finalInfo) || !os.SameFile(currentInfo, finalInfo) {
		cleanupPublished()
		return BuildResult{}, errors.New("published bundle final identity, mode, size, or link count is invalid")
	}
	if err := temporary.Close(); err != nil {
		cleanupPublished()
		return BuildResult{}, fmt.Errorf("close completed bundle: %w", err)
	}
	published = false
	packageDigest := sha256.Sum256(packageJSON)
	return BuildResult{
		OutputPath: outputPath, Size: info.Size(), SHA256: hex.EncodeToString(hasher.Sum(nil)),
		PackageJSONSHA256: hex.EncodeToString(packageDigest[:]), Package: clonePackage(metadata),
	}, nil
}

func marshalPackage(metadata Package) ([]byte, error) {
	raw, err := json.Marshal(metadata)
	if err != nil {
		return nil, fmt.Errorf("encode package metadata: %w", err)
	}
	raw = append(raw, '\n')
	if int64(len(raw)) > maxPackageJSONSize {
		return nil, errors.New("package.json exceeds its size bound")
	}
	return raw, nil
}

func writeMember(writer *tar.Writer, name string, mode uint32, content []byte, modTime time.Time) error {
	header := &tar.Header{
		Name: name, Mode: int64(mode), Uid: 0, Gid: 0, Size: int64(len(content)),
		ModTime: modTime.UTC(), AccessTime: time.Time{}, ChangeTime: time.Time{},
		Typeflag: tar.TypeReg, Format: tar.FormatUSTAR,
	}
	if err := writer.WriteHeader(header); err != nil {
		return fmt.Errorf("write canonical USTAR header for %s: %w", name, err)
	}
	if _, err := writer.Write(content); err != nil {
		return fmt.Errorf("write canonical USTAR payload for %s: %w", name, err)
	}
	return nil
}

func exactArchiveSize(packageSize, verifierSize int64) (int64, error) {
	if packageSize <= 0 || packageSize > maxPackageJSONSize || verifierSize <= 0 || verifierSize > maxVerifierSize {
		return 0, errors.New("verifier bundle member size is outside the supported bound")
	}
	total := tarBlockSize + paddedSize(packageSize) + tarBlockSize + paddedSize(verifierSize) + 2*tarBlockSize
	if total <= 0 || total > MaxArchiveSize {
		return 0, errors.New("verifier bundle archive exceeds the supported bound")
	}
	return total, nil
}

func paddedSize(size int64) int64 {
	if remainder := size % tarBlockSize; remainder != 0 {
		return size + tarBlockSize - remainder
	}
	return size
}

func prepareOutputPath(raw string) (outputPath, parentPath, outputName string, err error) {
	if strings.TrimSpace(raw) == "" {
		return "", "", "", errors.New("output path is required")
	}
	outputPath, err = filepath.Abs(strings.TrimSpace(raw))
	if err != nil {
		return "", "", "", err
	}
	outputPath = filepath.Clean(outputPath)
	parentPath, outputName = filepath.Split(outputPath)
	parentPath = filepath.Clean(parentPath)
	if outputName == "" || outputName == "." || outputName == ".." {
		return "", "", "", errors.New("output path must name a new regular file")
	}
	return outputPath, parentPath, outputName, nil
}

func randomName(prefix string) (string, error) {
	var value [18]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", fmt.Errorf("generate private staging name: %w", err)
	}
	return prefix + hex.EncodeToString(value[:]), nil
}

func exactRegularMode(info os.FileInfo, mode os.FileMode) bool {
	return info != nil && info.Mode()&os.ModeSymlink == 0 && info.Mode().IsRegular() &&
		info.Mode().Perm() == mode && info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) == 0
}

func fileSize(info os.FileInfo) int64 {
	if info == nil {
		return -1
	}
	return info.Size()
}
