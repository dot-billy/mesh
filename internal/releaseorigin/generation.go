package releaseorigin

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"

	releasetrust "mesh/internal/release"
)

const (
	GenerationSchema      = "mesh-release-origin-generation-v1"
	GenerationReceiptName = "generation.json"
	GenerationIndexName   = "origin-index.json"
	GenerationRepoName    = "repository"
	MaxGenerationReceipt  = 4096
	generationFileMode    = 0o444
	generationDirMode     = 0o555
	stagingPrefix         = ".mesh-origin-generation."
)

type GenerationReceipt struct {
	Schema      string `json:"schema"`
	Generation  string `json:"generation"`
	IndexSHA256 string `json:"index_sha256"`
	ObjectCount int    `json:"object_count"`
	TotalSize   int64  `json:"total_size"`
}

func EncodeGenerationReceipt(receipt GenerationReceipt) ([]byte, error) {
	if err := validateGenerationReceipt(receipt); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(receipt)
	if err != nil {
		return nil, fmt.Errorf("encode release origin generation receipt: %w", err)
	}
	raw = append(raw, '\n')
	if len(raw) > MaxGenerationReceipt {
		return nil, fmt.Errorf("release origin generation receipt exceeds %d bytes", MaxGenerationReceipt)
	}
	return raw, nil
}

func ParseGenerationReceipt(raw []byte) (GenerationReceipt, error) {
	if len(raw) == 0 || len(raw) > MaxGenerationReceipt {
		return GenerationReceipt{}, fmt.Errorf("release origin generation receipt size must be between 1 and %d bytes", MaxGenerationReceipt)
	}
	if err := releasetrust.ValidateStrictJSON(raw); err != nil {
		return GenerationReceipt{}, fmt.Errorf("invalid release origin generation receipt JSON: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var receipt GenerationReceipt
	if err := decoder.Decode(&receipt); err != nil {
		return GenerationReceipt{}, fmt.Errorf("decode release origin generation receipt: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return GenerationReceipt{}, errors.New("release origin generation receipt contains trailing content")
	}
	if err := validateGenerationReceipt(receipt); err != nil {
		return GenerationReceipt{}, err
	}
	canonical, err := EncodeGenerationReceipt(receipt)
	if err != nil {
		return GenerationReceipt{}, err
	}
	if !bytes.Equal(raw, canonical) {
		return GenerationReceipt{}, errors.New("release origin generation receipt must be canonical compact JSON followed by one LF")
	}
	return receipt, nil
}

func validateGenerationReceipt(receipt GenerationReceipt) error {
	if receipt.Schema != GenerationSchema {
		return fmt.Errorf("unsupported release origin generation schema %q", receipt.Schema)
	}
	if !validDigest(receipt.Generation) || !validDigest(receipt.IndexSHA256) || receipt.Generation != receipt.IndexSHA256 {
		return errors.New("release origin generation and index SHA-256 must be the same 64 lowercase hexadecimal characters")
	}
	if receipt.ObjectCount < 1 || receipt.ObjectCount > MaxObjects {
		return fmt.Errorf("release origin generation object count must be between 1 and %d", MaxObjects)
	}
	if receipt.TotalSize < 1 {
		return errors.New("release origin generation total size must be positive")
	}
	return nil
}

func validDigest(value string) bool {
	digest, err := hex.DecodeString(value)
	return err == nil && len(digest) == sha256.Size && hex.EncodeToString(digest) == value
}

// PublishGeneration copies exactly the objects named by indexPath into one
// content-addressed, read-only generation and publishes it without replacement.
// The no-replace directory transition is supported only on Linux.
func PublishGeneration(sourceRoot, indexPath, generationsRoot string) (publishedReceipt GenerationReceipt, publishedPath string, returnErr error) {
	if err := validateRoot(sourceRoot); err != nil {
		return GenerationReceipt{}, "", err
	}
	if err := validateGenerationParent(generationsRoot); err != nil {
		return GenerationReceipt{}, "", err
	}
	indexRaw, err := readStableIndex(indexPath)
	if err != nil {
		return GenerationReceipt{}, "", err
	}
	index, err := Parse(indexRaw)
	if err != nil {
		return GenerationReceipt{}, "", err
	}
	indexDigest := sha256.Sum256(indexRaw)
	generationID := hex.EncodeToString(indexDigest[:])
	totalSize, err := indexedTotalSize(index)
	if err != nil {
		return GenerationReceipt{}, "", err
	}
	receipt := GenerationReceipt{
		Schema: GenerationSchema, Generation: generationID, IndexSHA256: generationID,
		ObjectCount: len(index.Objects), TotalSize: totalSize,
	}
	finalPath := filepath.Join(generationsRoot, generationID)
	if _, err := os.Lstat(finalPath); err == nil {
		return GenerationReceipt{}, "", fmt.Errorf("release origin generation %s already exists", generationID)
	} else if !errors.Is(err, os.ErrNotExist) {
		return GenerationReceipt{}, "", fmt.Errorf("inspect release origin generation destination: %w", err)
	}

	stagingPath, err := os.MkdirTemp(generationsRoot, stagingPrefix)
	if err != nil {
		return GenerationReceipt{}, "", fmt.Errorf("create release origin generation staging directory: %w", err)
	}
	cleanup := true
	defer func() {
		if cleanup {
			returnErr = errors.Join(returnErr, removeGenerationStaging(generationsRoot, stagingPath))
		}
	}()
	repositoryPath := filepath.Join(stagingPath, GenerationRepoName)
	if err := os.Mkdir(repositoryPath, 0o755); err != nil {
		return GenerationReceipt{}, "", fmt.Errorf("create release origin generation repository: %w", err)
	}
	for _, object := range index.Objects {
		if err := copyIndexedObject(sourceRoot, repositoryPath, object); err != nil {
			return GenerationReceipt{}, "", err
		}
	}
	if err := writeGenerationFile(filepath.Join(stagingPath, GenerationIndexName), indexRaw); err != nil {
		return GenerationReceipt{}, "", err
	}
	receiptRaw, err := EncodeGenerationReceipt(receipt)
	if err != nil {
		return GenerationReceipt{}, "", err
	}
	if err := writeGenerationFile(filepath.Join(stagingPath, GenerationReceiptName), receiptRaw); err != nil {
		return GenerationReceipt{}, "", err
	}
	if err := sealGenerationTree(stagingPath); err != nil {
		return GenerationReceipt{}, "", err
	}
	if _, err := inspectGeneration(stagingPath, false); err != nil {
		return GenerationReceipt{}, "", fmt.Errorf("validate staged release origin generation: %w", err)
	}
	if err := renameGenerationNoReplace(generationsRoot, filepath.Base(stagingPath), generationID); err != nil {
		return GenerationReceipt{}, "", fmt.Errorf("publish release origin generation without replacement: %w", err)
	}
	cleanup = false
	if err := syncDirectory(generationsRoot); err != nil {
		return receipt, finalPath, fmt.Errorf("sync published release origin generation parent: %w", err)
	}
	return receipt, finalPath, nil
}

func InspectGeneration(generationPath string) (GenerationReceipt, error) {
	return inspectGeneration(generationPath, true)
}

// LoadGeneration returns the exact canonical index after a complete generation
// inspection. Callers that perform work from the returned index should inspect
// the generation again before claiming success if local mutation is in scope.
func LoadGeneration(generationPath string) (GenerationReceipt, Index, error) {
	receipt, err := InspectGeneration(generationPath)
	if err != nil {
		return GenerationReceipt{}, Index{}, err
	}
	indexRaw, err := readStableGenerationFile(filepath.Join(generationPath, GenerationIndexName), MaxIndexSize, "index")
	if err != nil {
		return GenerationReceipt{}, Index{}, err
	}
	digest := sha256.Sum256(indexRaw)
	if hex.EncodeToString(digest[:]) != receipt.IndexSHA256 {
		return GenerationReceipt{}, Index{}, errors.New("release origin generation index changed after inspection")
	}
	index, err := Parse(indexRaw)
	if err != nil {
		return GenerationReceipt{}, Index{}, err
	}
	return receipt, index, nil
}

func inspectGeneration(generationPath string, requireName bool) (GenerationReceipt, error) {
	if !filepath.IsAbs(generationPath) || filepath.Clean(generationPath) != generationPath || filepath.Base(generationPath) == string(filepath.Separator) {
		return GenerationReceipt{}, errors.New("release origin generation must be a clean absolute non-root directory")
	}
	if err := rejectSymlinkPath(generationPath, true); err != nil {
		return GenerationReceipt{}, err
	}
	receiptRaw, err := readStableGenerationFile(filepath.Join(generationPath, GenerationReceiptName), MaxGenerationReceipt, "receipt")
	if err != nil {
		return GenerationReceipt{}, err
	}
	receipt, err := ParseGenerationReceipt(receiptRaw)
	if err != nil {
		return GenerationReceipt{}, err
	}
	if requireName && filepath.Base(generationPath) != receipt.Generation {
		return GenerationReceipt{}, errors.New("release origin generation directory name does not match its receipt")
	}
	indexPath := filepath.Join(generationPath, GenerationIndexName)
	indexRaw, err := readStableGenerationFile(indexPath, MaxIndexSize, "index")
	if err != nil {
		return GenerationReceipt{}, err
	}
	digest := sha256.Sum256(indexRaw)
	if hex.EncodeToString(digest[:]) != receipt.IndexSHA256 {
		return GenerationReceipt{}, errors.New("release origin generation index SHA-256 does not match its receipt")
	}
	index, err := Parse(indexRaw)
	if err != nil {
		return GenerationReceipt{}, err
	}
	totalSize, err := indexedTotalSize(index)
	if err != nil {
		return GenerationReceipt{}, err
	}
	if len(index.Objects) != receipt.ObjectCount || totalSize != receipt.TotalSize {
		return GenerationReceipt{}, errors.New("release origin generation index totals do not match its receipt")
	}
	if err := validateExactGenerationTree(generationPath, index); err != nil {
		return GenerationReceipt{}, err
	}
	store, err := Open(filepath.Join(generationPath, GenerationRepoName), indexRaw)
	if err != nil {
		return GenerationReceipt{}, err
	}
	if err := store.CheckReadiness(); err != nil {
		_ = store.Close()
		return GenerationReceipt{}, err
	}
	if err := store.Close(); err != nil {
		return GenerationReceipt{}, fmt.Errorf("close inspected release origin generation: %w", err)
	}
	return receipt, nil
}

func validateGenerationParent(path string) error {
	if err := validateRoot(path); err != nil {
		return fmt.Errorf("invalid release origin generations root: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect release origin generations root: %w", err)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return errors.New("release origin generations root must not be writable by group or other")
	}
	return nil
}

func indexedTotalSize(index Index) (int64, error) {
	var total int64
	for _, object := range index.Objects {
		if object.Size > math.MaxInt64-total {
			return 0, errors.New("release origin generation total size overflows int64")
		}
		total += object.Size
	}
	return total, nil
}

func copyIndexedObject(sourceRoot, destinationRoot string, object Object) (returnErr error) {
	source, identity, err := openStableObject(sourceRoot, object.Path)
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, source.Close()) }()
	if identity.size != object.Size {
		return fmt.Errorf("release origin object %q size is %d, index requires %d", object.Path, identity.size, object.Size)
	}
	destinationPath := objectFilesystemPath(destinationRoot, object.Path)
	if err := os.MkdirAll(filepath.Dir(destinationPath), 0o755); err != nil {
		return fmt.Errorf("create release origin generation object directory: %w", err)
	}
	destination, err := os.OpenFile(destinationPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, generationFileMode)
	if err != nil {
		return fmt.Errorf("create release origin generation object %q: %w", object.Path, err)
	}
	closed := false
	defer func() {
		if !closed {
			returnErr = errors.Join(returnErr, destination.Close())
		}
	}()
	hasher := sha256.New()
	written, err := io.Copy(io.MultiWriter(destination, hasher), io.NewSectionReader(source, 0, identity.size))
	if err != nil || written != identity.size {
		return fmt.Errorf("copy release origin generation object %q: wrote %d of %d bytes: %w", object.Path, written, identity.size, err)
	}
	finalSource, err := source.Stat()
	if err != nil || !sameObjectFile(identity.info, finalSource) {
		return fmt.Errorf("release origin object %q changed while copying", object.Path)
	}
	if hex.EncodeToString(hasher.Sum(nil)) != object.SHA256 {
		return fmt.Errorf("release origin object %q SHA-256 differs from its index", object.Path)
	}
	if err := destination.Sync(); err != nil {
		return fmt.Errorf("sync release origin generation object %q: %w", object.Path, err)
	}
	if err := destination.Chmod(generationFileMode); err != nil {
		return fmt.Errorf("set release origin generation object %q mode: %w", object.Path, err)
	}
	if err := destination.Sync(); err != nil {
		return fmt.Errorf("sync release origin generation object %q mode: %w", object.Path, err)
	}
	if err := destination.Close(); err != nil {
		return fmt.Errorf("close release origin generation object %q: %w", object.Path, err)
	}
	closed = true
	return syncDirectory(filepath.Dir(destinationPath))
}

func writeGenerationFile(path string, raw []byte) (returnErr error) {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, generationFileMode)
	if err != nil {
		return fmt.Errorf("create release origin generation file %q: %w", filepath.Base(path), err)
	}
	closed := false
	defer func() {
		if !closed {
			returnErr = errors.Join(returnErr, file.Close())
		}
	}()
	written, err := file.Write(raw)
	if err != nil || written != len(raw) {
		return fmt.Errorf("write release origin generation file %q: wrote %d of %d bytes: %w", filepath.Base(path), written, len(raw), err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync release origin generation file %q: %w", filepath.Base(path), err)
	}
	if err := file.Chmod(generationFileMode); err != nil {
		return fmt.Errorf("set release origin generation file %q mode: %w", filepath.Base(path), err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync release origin generation file %q mode: %w", filepath.Base(path), err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close release origin generation file %q: %w", filepath.Base(path), err)
	}
	closed = true
	return syncDirectory(filepath.Dir(path))
}

func sealGenerationTree(root string) error {
	var directories []string
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			directories = append(directories, path)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("walk release origin generation before sealing: %w", err)
	}
	sort.Slice(directories, func(i, j int) bool { return len(directories[i]) > len(directories[j]) })
	for _, directory := range directories {
		if err := os.Chmod(directory, generationDirMode); err != nil {
			return fmt.Errorf("seal release origin generation directory: %w", err)
		}
		if err := syncDirectory(directory); err != nil {
			return fmt.Errorf("sync sealed release origin generation directory: %w", err)
		}
	}
	return nil
}

func validateExactGenerationTree(root string, index Index) error {
	expectedDirectories := map[string]bool{root: false, filepath.Join(root, GenerationRepoName): false}
	expectedFiles := map[string]bool{
		filepath.Join(root, GenerationReceiptName): false,
		filepath.Join(root, GenerationIndexName):   false,
	}
	for _, object := range index.Objects {
		path := objectFilesystemPath(filepath.Join(root, GenerationRepoName), object.Path)
		expectedFiles[path] = false
		for directory := filepath.Dir(path); strings.HasPrefix(directory, filepath.Join(root, GenerationRepoName)); directory = filepath.Dir(directory) {
			expectedDirectories[directory] = false
			if directory == filepath.Join(root, GenerationRepoName) {
				break
			}
		}
	}
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("release origin generation contains symlink %q", path)
		}
		if info.IsDir() {
			if _, ok := expectedDirectories[path]; !ok {
				return fmt.Errorf("release origin generation contains unindexed directory %q", path)
			}
			if info.Mode().Perm() != generationDirMode {
				return fmt.Errorf("release origin generation directory %q mode is %04o, want %04o", path, info.Mode().Perm(), generationDirMode)
			}
			expectedDirectories[path] = true
			return nil
		}
		if _, ok := expectedFiles[path]; !ok {
			return fmt.Errorf("release origin generation contains unindexed file %q", path)
		}
		if !info.Mode().IsRegular() || !singleLink(info) || info.Mode().Perm() != generationFileMode {
			return fmt.Errorf("release origin generation file %q must be a read-only single-link regular file", path)
		}
		expectedFiles[path] = true
		return nil
	})
	if err != nil {
		return err
	}
	for path, found := range expectedDirectories {
		if !found {
			return fmt.Errorf("release origin generation is missing directory %q", path)
		}
	}
	for path, found := range expectedFiles {
		if !found {
			return fmt.Errorf("release origin generation is missing file %q", path)
		}
	}
	return nil
}

func readStableGenerationFile(path string, maximum int64, label string) ([]byte, error) {
	if err := rejectSymlinkPath(path, false); err != nil {
		return nil, err
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect release origin generation %s: %w", label, err)
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || before.Size() < 1 || before.Size() > maximum || !singleLink(before) {
		return nil, fmt.Errorf("release origin generation %s must be one bounded single-link regular file", label)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open release origin generation %s: %w", label, err)
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !sameObjectFile(before, after) {
		return nil, fmt.Errorf("release origin generation %s changed while opening", label)
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || len(raw) < 1 || int64(len(raw)) > maximum {
		return nil, fmt.Errorf("read bounded release origin generation %s", label)
	}
	final, err := file.Stat()
	if err != nil || !sameObjectFile(after, final) {
		return nil, fmt.Errorf("release origin generation %s changed while reading", label)
	}
	return raw, nil
}

func removeGenerationStaging(parent, path string) error {
	if filepath.Dir(path) != parent || !strings.HasPrefix(filepath.Base(path), stagingPrefix) {
		return errors.New("refuse to remove an unrecognized release origin generation staging path")
	}
	var directories []string
	_ = filepath.WalkDir(path, func(current string, entry os.DirEntry, walkErr error) error {
		if walkErr == nil && entry.IsDir() {
			directories = append(directories, current)
		}
		return nil
	})
	sort.Slice(directories, func(i, j int) bool { return len(directories[i]) > len(directories[j]) })
	for _, directory := range directories {
		_ = os.Chmod(directory, 0o700)
	}
	return os.RemoveAll(path)
}
