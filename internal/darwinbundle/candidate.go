package darwinbundle

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const CandidateInspectionSchema = "mesh-darwin-security-candidate-inspection-v1"

// CandidateInspection is structural and build-policy evidence for an unsigned
// Darwin staging bundle. It grants no release or Darwin host authority.
type CandidateInspection struct {
	Schema            string  `json:"schema"`
	ArtifactSHA256    string  `json:"artifact_sha256"`
	ArtifactSize      int64   `json:"artifact_size"`
	PackageJSONSHA256 string  `json:"package_json_sha256"`
	FileCount         int     `json:"file_count"`
	DirectoryCount    int     `json:"directory_count"`
	TotalBytes        int64   `json:"total_bytes"`
	Package           Package `json:"package"`
}

// InspectCandidateFile stably snapshots, fully validates, and stages one exact
// bundle into an existing empty 0700 directory. Selection fields are derived
// only for security analysis; threshold metadata remains release authority.
func InspectCandidateFile(artifactPath, outputDirectory string) (CandidateInspection, error) {
	if !cleanAbsolutePath(artifactPath) || !cleanAbsolutePath(outputDirectory) {
		return CandidateInspection{}, errors.New("candidate artifact and output directory must be clean absolute non-root paths")
	}
	if resolved, err := filepath.EvalSymlinks(artifactPath); err != nil || resolved != artifactPath {
		return CandidateInspection{}, errors.New("candidate artifact path cannot traverse symlinks")
	}
	if resolved, err := filepath.EvalSymlinks(outputDirectory); err != nil || resolved != outputDirectory {
		return CandidateInspection{}, errors.New("candidate output path cannot traverse symlinks")
	}
	before, err := os.Lstat(artifactPath)
	if err != nil || !before.Mode().IsRegular() || !singleLink(before) || before.Size() < 1 || before.Size() > MaxArchiveSize ||
		before.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || before.Mode().Perm()&0o022 != 0 {
		return CandidateInspection{}, errors.New("candidate artifact must be one bounded single-link regular file without special bits or group/other write access")
	}
	outputBefore, err := os.Lstat(outputDirectory)
	if err != nil || !outputBefore.IsDir() || outputBefore.Mode().Perm() != 0o700 || outputBefore.Mode()&os.ModeSymlink != 0 {
		return CandidateInspection{}, errors.New("candidate output must be an existing real 0700 directory")
	}
	file, err := os.Open(artifactPath)
	if err != nil {
		return CandidateInspection{}, fmt.Errorf("open candidate artifact: %w", err)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !stableCandidateInfo(before, opened) {
		return CandidateInspection{}, errors.New("candidate artifact changed while opening")
	}
	raw, err := io.ReadAll(io.LimitReader(file, MaxArchiveSize+1))
	if err != nil || int64(len(raw)) != opened.Size() || len(raw) == 0 || int64(len(raw)) > MaxArchiveSize {
		return CandidateInspection{}, errors.New("candidate artifact changed or exceeded its bound while reading")
	}
	after, err := file.Stat()
	pathAfter, pathErr := os.Lstat(artifactPath)
	if err != nil || pathErr != nil || !stableCandidateInfo(opened, after) || !stableCandidateInfo(opened, pathAfter) {
		return CandidateInspection{}, errors.New("candidate artifact changed during snapshot")
	}
	root, err := os.OpenRoot(outputDirectory)
	if err != nil {
		return CandidateInspection{}, fmt.Errorf("anchor candidate output: %w", err)
	}
	defer root.Close()
	anchoredOutput, err := root.Stat(".")
	if err != nil || !os.SameFile(outputBefore, anchoredOutput) {
		return CandidateInspection{}, errors.New("candidate output changed while anchoring")
	}
	inspection, err := inspectAndStageCandidate(raw, root)
	if err != nil {
		return CandidateInspection{}, err
	}
	digest := sha256.Sum256(raw)
	inspection.Schema = CandidateInspectionSchema
	inspection.ArtifactSHA256 = hex.EncodeToString(digest[:])
	inspection.ArtifactSize = int64(len(raw))
	return inspection, nil
}

// ValidateCandidateInspection revalidates the complete deterministic evidence
// needed to authenticate an already-staged candidate after process restart.
// It does not grant release authority; callers must still bind ArtifactSHA256
// and the selected platform to threshold-authenticated release metadata.
func ValidateCandidateInspection(inspection CandidateInspection) error {
	if inspection.Schema != CandidateInspectionSchema {
		return errors.New("Darwin candidate inspection schema is invalid")
	}
	if !digestPattern.MatchString(inspection.ArtifactSHA256) || inspection.ArtifactSize < 1 || inspection.ArtifactSize > MaxArchiveSize {
		return errors.New("Darwin candidate inspection artifact identity is invalid")
	}
	if !digestPattern.MatchString(inspection.PackageJSONSHA256) {
		return errors.New("Darwin candidate inspection package digest is invalid")
	}
	if _, err := validatePackage(inspection.Package); err != nil {
		return fmt.Errorf("Darwin candidate inspection package: %w", err)
	}
	packageJSON, err := marshalPackage(inspection.Package)
	if err != nil {
		return err
	}
	packageDigest := sha256.Sum256(packageJSON)
	if hex.EncodeToString(packageDigest[:]) != inspection.PackageJSONSHA256 {
		return errors.New("Darwin candidate inspection package digest differs from its canonical package")
	}
	wantArchiveSize, err := exactArchiveSize(int64(len(packageJSON)), inspection.Package.Entries)
	if err != nil || wantArchiveSize != inspection.ArtifactSize {
		return errors.New("Darwin candidate inspection artifact size differs from its canonical archive")
	}
	wantTotal := int64(len(packageJSON))
	for _, entry := range inspection.Package.Entries {
		if wantTotal > maxPayloadSize+maxPackageJSONSize-entry.Size {
			return errors.New("Darwin candidate inspection staged byte count overflows its bound")
		}
		wantTotal += entry.Size
	}
	if inspection.FileCount != len(inspection.Package.Entries)+1 ||
		inspection.DirectoryCount != len(candidateDirectories(inspection.Package.Target.Arch)) ||
		inspection.TotalBytes != wantTotal {
		return errors.New("Darwin candidate inspection topology or byte count is inconsistent")
	}
	return nil
}

// ReconstructCandidateInspection rebuilds the exact inspection needed to
// reauthenticate an already-published release from its immutable package.json
// and the artifact digest retained in installer state. Canonical archive size
// and staged topology are derived, never accepted from the filesystem.
func ReconstructCandidateInspection(artifactSHA256 string, packageJSON []byte) (CandidateInspection, error) {
	metadata, err := parsePackage(packageJSON)
	if err != nil {
		return CandidateInspection{}, err
	}
	packageDigest := sha256.Sum256(packageJSON)
	artifactSize, err := exactArchiveSize(int64(len(packageJSON)), metadata.Entries)
	if err != nil {
		return CandidateInspection{}, err
	}
	totalBytes := int64(len(packageJSON))
	for _, entry := range metadata.Entries {
		if totalBytes > maxPayloadSize+maxPackageJSONSize-entry.Size {
			return CandidateInspection{}, errors.New("Darwin reconstructed candidate byte count overflows its bound")
		}
		totalBytes += entry.Size
	}
	inspection := CandidateInspection{
		Schema: CandidateInspectionSchema, ArtifactSHA256: artifactSHA256, ArtifactSize: artifactSize,
		PackageJSONSHA256: hex.EncodeToString(packageDigest[:]), FileCount: len(metadata.Entries) + 1,
		DirectoryCount: len(candidateDirectories(metadata.Target.Arch)), TotalBytes: totalBytes, Package: clonePackage(metadata),
	}
	if err := ValidateCandidateInspection(inspection); err != nil {
		return CandidateInspection{}, err
	}
	return inspection, nil
}

func inspectAndStageCandidate(raw []byte, root *os.Root) (result CandidateInspection, returnErr error) {
	if root == nil {
		return result, errors.New("candidate staging root is required")
	}
	children, err := fs.ReadDir(root.FS(), ".")
	if err != nil || len(children) != 0 {
		return result, errors.New("candidate staging root must be empty")
	}
	reader := tar.NewReader(bytes.NewReader(raw))
	packageHeader, err := reader.Next()
	if err != nil || !exactUSTARHeader(packageHeader, packageJSONPath, packageJSONArchiveMode, packageHeaderSize(packageHeader), nil) ||
		packageHeader.Size < 1 || packageHeader.Size > maxPackageJSONSize {
		return result, errors.New("candidate archive must begin with canonical bounded USTAR package.json")
	}
	packageJSON, err := readExactMember(reader, packageHeader.Size)
	if err != nil {
		return result, fmt.Errorf("read candidate package.json: %w", err)
	}
	metadata, err := parsePackage(packageJSON)
	if err != nil {
		return result, err
	}
	buildTime, _ := validatePackage(metadata)
	if !exactUSTARHeader(packageHeader, packageJSONPath, packageJSONArchiveMode, int64(len(packageJSON)), &buildTime) {
		return result, errors.New("candidate package.json USTAR header is not canonical")
	}
	policy, err := productionPolicy(metadata.Target.Arch)
	if err != nil {
		return result, err
	}
	if err := policy.validateMetadata(metadata); err != nil {
		return result, err
	}
	wantSize, err := exactArchiveSize(int64(len(packageJSON)), metadata.Entries)
	if err != nil || int64(len(raw)) != wantSize {
		return result, fmt.Errorf("archive size is %d bytes, canonical size is %d", len(raw), wantSize)
	}
	contents := make(map[string][]byte, len(metadata.Entries))
	for _, entry := range metadata.Entries {
		header, err := reader.Next()
		if err != nil || !exactUSTARHeader(header, entry.Path, entry.ArchiveMode, entry.Size, &buildTime) {
			return result, fmt.Errorf("payload %q USTAR header is not canonical", entry.Path)
		}
		content, err := readExactMember(reader, entry.Size)
		if err != nil {
			return result, fmt.Errorf("read candidate payload %q: %w", entry.Path, err)
		}
		if err := policy.validateContent(entry.Path, content, metadata); err != nil {
			return result, err
		}
		contents[entry.Path] = content
		result.TotalBytes += entry.Size
	}
	if _, err := reader.Next(); !errors.Is(err, io.EOF) {
		return result, errors.New("candidate archive has a trailing member or malformed terminator")
	}
	canonicalHash := sha256.New()
	counted := &countWriter{writer: canonicalHash}
	writer := tar.NewWriter(counted)
	if err := writeMember(writer, packageJSONPath, packageJSONArchiveMode, packageJSON, buildTime); err != nil {
		return result, err
	}
	for _, entry := range metadata.Entries {
		if err := writeMember(writer, entry.Path, entry.ArchiveMode, contents[entry.Path], buildTime); err != nil {
			return result, err
		}
	}
	if err := writer.Close(); err != nil {
		return result, fmt.Errorf("reconstruct canonical candidate: %w", err)
	}
	artifactDigest := sha256.Sum256(raw)
	if counted.count != int64(len(raw)) || !bytes.Equal(canonicalHash.Sum(nil), artifactDigest[:]) {
		return result, errors.New("candidate archive bytes differ from canonical USTAR reconstruction")
	}
	directories := candidateDirectories(metadata.Target.Arch)
	if err := stageCandidateTree(root, directories, packageJSON, metadata, contents); err != nil {
		return result, err
	}
	packageDigest := sha256.Sum256(packageJSON)
	result.PackageJSONSHA256 = hex.EncodeToString(packageDigest[:])
	result.FileCount = len(metadata.Entries) + 1
	result.DirectoryCount = len(directories)
	result.TotalBytes += int64(len(packageJSON))
	result.Package = clonePackage(metadata)
	return result, nil
}

type countWriter struct {
	writer io.Writer
	count  int64
}

func (writer *countWriter) Write(content []byte) (int, error) {
	written, err := writer.writer.Write(content)
	writer.count += int64(written)
	return written, err
}

func packageHeaderSize(header *tar.Header) int64 {
	if header == nil {
		return 0
	}
	return header.Size
}

func exactUSTARHeader(header *tar.Header, name string, mode uint32, size int64, buildTime *time.Time) bool {
	if header == nil || header.Name != name || header.Mode != int64(mode) || header.Size != size || header.Typeflag != tar.TypeReg ||
		header.Format != tar.FormatUSTAR || header.Uid != 0 || header.Gid != 0 || header.Uname != "" || header.Gname != "" ||
		header.Linkname != "" || header.Devmajor != 0 || header.Devminor != 0 || len(header.PAXRecords) != 0 ||
		!header.AccessTime.IsZero() || !header.ChangeTime.IsZero() {
		return false
	}
	if buildTime == nil {
		return true
	}
	return header.ModTime.Equal(*buildTime)
}

func readExactMember(reader io.Reader, size int64) ([]byte, error) {
	if size < 1 || size > maxPayloadFileSize && size > maxPackageJSONSize {
		return nil, errors.New("archive member size is outside the supported bound")
	}
	content, err := io.ReadAll(io.LimitReader(reader, size+1))
	if err != nil || int64(len(content)) != size {
		return nil, errors.New("archive member length differs from its header")
	}
	return content, nil
}

func candidateDirectories(arch string) []string {
	set := make(map[string]struct{})
	for _, spec := range payloadSpecs(arch) {
		for parent := path.Dir(spec.path); parent != "."; parent = path.Dir(parent) {
			set[parent] = struct{}{}
		}
	}
	directories := make([]string, 0, len(set))
	for directory := range set {
		directories = append(directories, directory)
	}
	sort.Slice(directories, func(left, right int) bool {
		leftDepth, rightDepth := strings.Count(directories[left], "/"), strings.Count(directories[right], "/")
		if leftDepth != rightDepth {
			return leftDepth < rightDepth
		}
		return directories[left] < directories[right]
	})
	return directories
}

func stageCandidateTree(root *os.Root, directories []string, packageJSON []byte, metadata Package, contents map[string][]byte) (returnErr error) {
	createdFiles := []string{}
	createdDirectories := []string{}
	defer func() {
		if returnErr == nil {
			return
		}
		_ = root.Chmod(".", 0o700)
		for index := len(createdDirectories) - 1; index >= 0; index-- {
			_ = root.Chmod(createdDirectories[index], 0o700)
		}
		for _, name := range createdFiles {
			_ = root.Remove(name)
		}
		for index := len(createdDirectories) - 1; index >= 0; index-- {
			_ = root.Remove(createdDirectories[index])
		}
	}()
	for _, directory := range directories {
		if err := root.Mkdir(directory, 0o700); err != nil {
			return fmt.Errorf("create candidate directory %q: %w", directory, err)
		}
		createdDirectories = append(createdDirectories, directory)
	}
	files := []struct {
		name    string
		mode    uint32
		content []byte
	}{{packageJSONPath, packageJSONArchiveMode, packageJSON}}
	for _, entry := range metadata.Entries {
		files = append(files, struct {
			name    string
			mode    uint32
			content []byte
		}{entry.Path, entry.ArchiveMode, contents[entry.Path]})
	}
	for _, staged := range files {
		file, err := root.OpenFile(staged.name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return fmt.Errorf("create candidate file %q: %w", staged.name, err)
		}
		createdFiles = append(createdFiles, staged.name)
		written, writeErr := file.Write(staged.content)
		chmodErr := file.Chmod(os.FileMode(staged.mode))
		syncErr := file.Sync()
		closeErr := file.Close()
		if writeErr != nil || written != len(staged.content) || chmodErr != nil || syncErr != nil || closeErr != nil {
			return fmt.Errorf("finish candidate file %q: write=%v chmod=%v sync=%v close=%v", staged.name, writeErr, chmodErr, syncErr, closeErr)
		}
		info, err := root.Lstat(staged.name)
		if err != nil || !exactRegularMode(info, staged.mode) || !singleLink(info) {
			return fmt.Errorf("candidate file %q did not retain its exact identity", staged.name)
		}
	}
	for index := len(directories) - 1; index >= 0; index-- {
		directoryName := directories[index]
		if err := root.Chmod(directoryName, 0o555); err != nil {
			return fmt.Errorf("seal candidate directory %q: %w", directoryName, err)
		}
		directory, err := root.Open(directoryName)
		if err != nil {
			return fmt.Errorf("open candidate directory %q for sync: %w", directoryName, err)
		}
		syncErr := directory.Sync()
		closeErr := directory.Close()
		if syncErr != nil || closeErr != nil {
			return fmt.Errorf("sync candidate directory %q: sync=%v close=%v", directoryName, syncErr, closeErr)
		}
	}
	if err := root.Chmod(".", 0o555); err != nil {
		return fmt.Errorf("seal candidate root: %w", err)
	}
	directory, err := root.Open(".")
	if err != nil {
		return fmt.Errorf("open candidate root for sync: %w", err)
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if syncErr != nil || closeErr != nil {
		return fmt.Errorf("sync candidate root: sync=%v close=%v", syncErr, closeErr)
	}
	return nil
}

func stableCandidateInfo(left, right os.FileInfo) bool {
	return left != nil && right != nil && os.SameFile(left, right) && left.Mode() == right.Mode() && left.Size() == right.Size() && left.ModTime().Equal(right.ModTime())
}

func cleanAbsolutePath(value string) bool {
	return filepath.IsAbs(value) && filepath.Clean(value) == value && value != string(filepath.Separator)
}
