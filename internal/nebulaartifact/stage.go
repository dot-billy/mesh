package nebulaartifact

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strings"
)

func stageArchive(archive *os.File, artifact ArtifactLock, root *os.Root) (int, int64, error) {
	if archive == nil || root == nil {
		return 0, 0, errors.New("archive file and staging root are required")
	}
	if _, err := archive.Seek(0, io.SeekStart); err != nil {
		return 0, 0, err
	}
	if err := prepareLockedDirectories(root, artifact.Entries); err != nil {
		return 0, 0, err
	}
	var count int
	var total int64
	var err error
	switch artifact.ArchiveFormat {
	case "tar.gz":
		count, total, err = stageTarGZ(archive, artifact, root)
	case "zip":
		count, total, err = stageZIP(archive, artifact, root)
	default:
		err = fmt.Errorf("unsupported archive format %q", artifact.ArchiveFormat)
	}
	if err != nil {
		return 0, 0, err
	}
	if err := applyLockedDirectoryModes(root, artifact.Entries); err != nil {
		return 0, 0, err
	}
	if err := syncStagedDirectories(root, artifact.Entries); err != nil {
		return 0, 0, err
	}
	return count, total, nil
}

func syncStagedDirectories(root *os.Root, entries []EntryLock) error {
	directories := make(map[string]struct{})
	for _, entry := range entries {
		name := outputPath(entry)
		if entry.Type == "dir" {
			directories[name] = struct{}{}
		}
		for parent := path.Dir(name); parent != "."; parent = path.Dir(parent) {
			directories[parent] = struct{}{}
		}
	}
	ordered := make([]string, 0, len(directories))
	for directory := range directories {
		ordered = append(ordered, directory)
	}
	sort.Slice(ordered, func(i, j int) bool {
		leftDepth, rightDepth := strings.Count(ordered[i], "/"), strings.Count(ordered[j], "/")
		if leftDepth == rightDepth {
			return ordered[i] > ordered[j]
		}
		return leftDepth > rightDepth
	})
	for _, directory := range ordered {
		if err := syncRootDirectory(root, directory); err != nil {
			return fmt.Errorf("sync staged directory %q: %w", directory, err)
		}
	}
	if err := syncRootDirectory(root, "."); err != nil {
		return fmt.Errorf("sync staging root: %w", err)
	}
	return nil
}

func prepareLockedDirectories(root *os.Root, entries []EntryLock) error {
	directories := make(map[string]struct{})
	for _, entry := range entries {
		name := outputPath(entry)
		if entry.Type == "dir" {
			directories[name] = struct{}{}
		}
		for parent := path.Dir(name); parent != "."; parent = path.Dir(parent) {
			directories[parent] = struct{}{}
		}
	}
	ordered := make([]string, 0, len(directories))
	for directory := range directories {
		ordered = append(ordered, directory)
	}
	sort.Slice(ordered, func(i, j int) bool {
		leftDepth := strings.Count(ordered[i], "/")
		rightDepth := strings.Count(ordered[j], "/")
		if leftDepth == rightDepth {
			return ordered[i] < ordered[j]
		}
		return leftDepth < rightDepth
	})
	for _, directory := range ordered {
		if err := root.Mkdir(directory, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("create locked directory %q: %w", directory, err)
		}
		info, err := root.Lstat(directory)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("locked directory %q is not a real directory", directory)
		}
	}
	return nil
}

func applyLockedDirectoryModes(root *os.Root, entries []EntryLock) error {
	for _, entry := range entries {
		if entry.Type != "dir" {
			continue
		}
		if err := root.Chmod(outputPath(entry), os.FileMode(entry.OutputMode)); err != nil {
			return fmt.Errorf("set directory mode for %q: %w", entry.Name, err)
		}
	}
	return nil
}

func stageTarGZ(archive *os.File, artifact ArtifactLock, root *os.Root) (int, int64, error) {
	bufferedArchive := bufio.NewReaderSize(archive, 32<<10)
	gzipReader, err := gzip.NewReader(bufferedArchive)
	if err != nil {
		return 0, 0, fmt.Errorf("open gzip stream: %w", err)
	}
	gzipReader.Multistream(false)
	tarReader := tar.NewReader(gzipReader)
	expected := entryMap(artifact.Entries)
	seen := make(map[string]struct{}, len(expected))
	var fileCount int
	var total int64
	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			_ = gzipReader.Close()
			return 0, 0, fmt.Errorf("read tar header: %w", err)
		}
		directory := header.Typeflag == tar.TypeDir
		if !directory && header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA {
			_ = gzipReader.Close()
			return 0, 0, fmt.Errorf("tar entry %q has forbidden type %d", header.Name, header.Typeflag)
		}
		if err := validateArchivePath(header.Name, directory); err != nil {
			_ = gzipReader.Close()
			return 0, 0, err
		}
		locked, ok := expected[header.Name]
		if !ok {
			_ = gzipReader.Close()
			return 0, 0, fmt.Errorf("unlisted tar entry %q", header.Name)
		}
		if _, duplicate := seen[header.Name]; duplicate {
			_ = gzipReader.Close()
			return 0, 0, fmt.Errorf("duplicate tar entry %q", header.Name)
		}
		seen[header.Name] = struct{}{}
		actualType := "file"
		if directory {
			actualType = "dir"
		}
		if locked.Type != actualType || header.Size != locked.Size || header.Mode < 0 || uint64(header.Mode)&^uint64(0o777) != 0 || uint32(header.Mode) != locked.ArchiveMode || header.Linkname != "" || header.Devmajor != 0 || header.Devminor != 0 {
			_ = gzipReader.Close()
			return 0, 0, fmt.Errorf("tar metadata mismatch for %q", header.Name)
		}
		if directory {
			continue
		}
		if err := writeVerifiedEntry(root, locked, tarReader); err != nil {
			_ = gzipReader.Close()
			return 0, 0, err
		}
		fileCount++
		total += locked.Size
		if total > maxExpandedSize {
			_ = gzipReader.Close()
			return 0, 0, errors.New("tar aggregate size exceeds policy")
		}
	}
	remaining, err := io.ReadAll(io.LimitReader(gzipReader, 64<<10+1))
	if err != nil {
		_ = gzipReader.Close()
		return 0, 0, fmt.Errorf("finish gzip stream: %w", err)
	}
	if len(remaining) > 64<<10 {
		_ = gzipReader.Close()
		return 0, 0, errors.New("tar padding exceeds policy")
	}
	for _, value := range remaining {
		if value != 0 {
			_ = gzipReader.Close()
			return 0, 0, errors.New("tar contains nonzero data after the end marker")
		}
	}
	if err := gzipReader.Close(); err != nil {
		return 0, 0, fmt.Errorf("close gzip stream: %w", err)
	}
	if _, err := bufferedArchive.Peek(1); err == nil {
		return 0, 0, errors.New("archive contains a second gzip member or trailing bytes")
	} else if !errors.Is(err, io.EOF) {
		return 0, 0, fmt.Errorf("check gzip boundary: %w", err)
	}
	if err := exactEntrySet(expected, seen); err != nil {
		return 0, 0, err
	}
	return fileCount, total, nil
}

func stageZIP(archive *os.File, artifact ArtifactLock, root *os.Root) (int, int64, error) {
	if err := verifyCanonicalZIPEnvelope(archive, artifact); err != nil {
		return 0, 0, err
	}
	zipReader, err := zip.NewReader(archive, artifact.Size)
	if err != nil {
		return 0, 0, fmt.Errorf("open ZIP: %w", err)
	}
	if len(zipReader.File) > maxEntries {
		return 0, 0, errors.New("ZIP entry count exceeds policy")
	}
	expected := entryMap(artifact.Entries)
	seen := make(map[string]struct{}, len(expected))
	var fileCount int
	var total int64
	for _, file := range zipReader.File {
		mode := file.Mode()
		directory := mode.IsDir()
		if !directory && !mode.IsRegular() {
			return 0, 0, fmt.Errorf("ZIP entry %q has forbidden type %s", file.Name, mode.Type())
		}
		if mode&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
			return 0, 0, fmt.Errorf("ZIP entry %q has forbidden special mode bits", file.Name)
		}
		if file.NonUTF8 || file.Flags&1 != 0 || file.Flags & ^uint16(0x808) != 0 {
			return 0, 0, fmt.Errorf("ZIP entry %q uses encrypted or unsupported flags", file.Name)
		}
		if err := validateArchivePath(file.Name, directory); err != nil {
			return 0, 0, err
		}
		locked, ok := expected[file.Name]
		if !ok {
			return 0, 0, fmt.Errorf("unlisted ZIP entry %q", file.Name)
		}
		if _, duplicate := seen[file.Name]; duplicate {
			return 0, 0, fmt.Errorf("duplicate ZIP entry %q", file.Name)
		}
		seen[file.Name] = struct{}{}
		actualType := "file"
		if directory {
			actualType = "dir"
		}
		if file.UncompressedSize64 > maxEntrySize || file.UncompressedSize64 > uint64(^uint64(0)>>1) || file.CompressedSize64 > uint64(^uint64(0)>>1) {
			return 0, 0, fmt.Errorf("ZIP entry %q exceeds size policy", file.Name)
		}
		if locked.Type != actualType || int64(file.UncompressedSize64) != locked.Size || uint32(mode.Perm()) != locked.ArchiveMode || int64(file.CompressedSize64) != locked.CompressedSize || file.CRC32 != locked.CRC32 || file.Method != locked.Compression {
			return 0, 0, fmt.Errorf("ZIP metadata mismatch for %q", file.Name)
		}
		if file.CompressedSize64 > 0 && file.UncompressedSize64 > uint64(maxCompressionRatio)*file.CompressedSize64+(1<<20) {
			return 0, 0, fmt.Errorf("ZIP entry %q exceeds compression-ratio policy", file.Name)
		}
		if directory {
			continue
		}
		reader, err := file.Open()
		if err != nil {
			return 0, 0, fmt.Errorf("open ZIP entry %q: %w", file.Name, err)
		}
		writeErr := writeVerifiedEntry(root, locked, reader)
		closeErr := reader.Close()
		if writeErr != nil {
			return 0, 0, writeErr
		}
		if closeErr != nil {
			return 0, 0, fmt.Errorf("close ZIP entry %q: %w", file.Name, closeErr)
		}
		fileCount++
		total += locked.Size
		if total > maxExpandedSize {
			return 0, 0, errors.New("ZIP aggregate size exceeds policy")
		}
	}
	if err := exactEntrySet(expected, seen); err != nil {
		return 0, 0, err
	}
	return fileCount, total, nil
}

func verifyCanonicalZIPEnvelope(archive *os.File, artifact ArtifactLock) error {
	if artifact.Size < 22 {
		return errors.New("ZIP is shorter than an end-of-central-directory record")
	}
	var first [4]byte
	if _, err := archive.ReadAt(first[:], 0); err != nil {
		return fmt.Errorf("read ZIP start: %w", err)
	}
	if binary.LittleEndian.Uint32(first[:]) != 0x04034b50 {
		return errors.New("ZIP does not begin with a local file header")
	}
	var end [22]byte
	if _, err := archive.ReadAt(end[:], artifact.Size-int64(len(end))); err != nil {
		return fmt.Errorf("read ZIP end: %w", err)
	}
	if binary.LittleEndian.Uint32(end[0:4]) != 0x06054b50 {
		return errors.New("ZIP does not have an exact standard end record at EOF")
	}
	disk := binary.LittleEndian.Uint16(end[4:6])
	centralDisk := binary.LittleEndian.Uint16(end[6:8])
	diskEntries := binary.LittleEndian.Uint16(end[8:10])
	totalEntries := binary.LittleEndian.Uint16(end[10:12])
	centralSize := binary.LittleEndian.Uint32(end[12:16])
	centralOffset := binary.LittleEndian.Uint32(end[16:20])
	commentLength := binary.LittleEndian.Uint16(end[20:22])
	if disk != 0 || centralDisk != 0 || diskEntries != totalEntries || int(totalEntries) != len(artifact.Entries) || commentLength != 0 {
		return errors.New("ZIP disk, entry-count, or comment metadata is not canonical")
	}
	if diskEntries == 0xffff || centralSize == 0xffffffff || centralOffset == 0xffffffff {
		return errors.New("ZIP64 envelope is not permitted for locked Nebula archives")
	}
	if uint64(centralOffset)+uint64(centralSize) != uint64(artifact.Size-22) {
		return errors.New("ZIP central directory is not contiguous with its EOF record")
	}
	return nil
}

func writeVerifiedEntry(root *os.Root, locked EntryLock, source io.Reader) (returnErr error) {
	name := outputPath(locked)
	destination, err := root.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, os.FileMode(locked.OutputMode))
	if err != nil {
		return fmt.Errorf("create staged entry %q: %w", name, err)
	}
	defer func() {
		if err := destination.Close(); err != nil && returnErr == nil {
			returnErr = fmt.Errorf("close staged entry %q: %w", name, err)
		}
	}()
	hash := sha256.New()
	written, err := io.Copy(io.MultiWriter(destination, hash), io.LimitReader(source, locked.Size+1))
	if err != nil {
		return fmt.Errorf("extract %q: %w", name, err)
	}
	if written != locked.Size {
		return fmt.Errorf("entry %q size is %d, want %d", name, written, locked.Size)
	}
	actualHash := hex.EncodeToString(hash.Sum(nil))
	if actualHash != locked.SHA256 {
		return fmt.Errorf("entry %q SHA-256 is %s, want %s", name, actualHash, locked.SHA256)
	}
	if err := destination.Sync(); err != nil {
		return fmt.Errorf("sync entry %q: %w", name, err)
	}
	if _, err := destination.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("rewind entry %q: %w", name, err)
	}
	if locked.Binary != nil {
		if err := verifyBinary(destination, *locked.Binary); err != nil {
			return fmt.Errorf("verify executable %q: %w", name, err)
		}
	}
	if err := destination.Chmod(os.FileMode(locked.OutputMode)); err != nil {
		return fmt.Errorf("set mode for %q: %w", name, err)
	}
	if err := destination.Sync(); err != nil {
		return fmt.Errorf("sync final metadata for %q: %w", name, err)
	}
	return nil
}

func entryMap(entries []EntryLock) map[string]EntryLock {
	result := make(map[string]EntryLock, len(entries))
	for _, entry := range entries {
		result[entry.Name] = entry
	}
	return result
}

func exactEntrySet(expected map[string]EntryLock, seen map[string]struct{}) error {
	if len(expected) != len(seen) {
		missing := make([]string, 0)
		for name := range expected {
			if _, ok := seen[name]; !ok {
				missing = append(missing, name)
			}
		}
		sort.Strings(missing)
		return fmt.Errorf("archive is missing locked entries: %s", strings.Join(missing, ", "))
	}
	return nil
}
