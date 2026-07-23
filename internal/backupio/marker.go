package backupio

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"
)

const maxMarkerSize = 8 << 10

const (
	restoreMarkerSuffix  = ".mesh-restore-incomplete"
	markerScanBatchSize  = 128
	maxMarkerScanEntries = 64 << 10
)

type restoreMarker struct {
	Schema      string    `json:"schema"`
	BackupID    string    `json:"backup_id"`
	OperationID string    `json:"operation_id"`
	Target      string    `json:"target"`
	CreatedAt   time.Time `json:"created_at"`
}

// RestoreMarkerPath returns the exact sibling marker path used to fence a
// target while an offline restore is in progress. It performs no filesystem
// writes and is safe for mesh-server startup checks.
func RestoreMarkerPath(targetDir string) (string, error) {
	if targetDir == "" || !utf8.ValidString(targetDir) || strings.IndexFunc(targetDir, func(character rune) bool { return character < 0x20 || character == 0x7f }) >= 0 || !filepath.IsAbs(targetDir) || filepath.Clean(targetDir) != targetDir {
		return "", errors.New("restore target must be a clean absolute path")
	}
	base := filepath.Base(targetDir)
	if base == "." || base == string(filepath.Separator) || base == "" {
		return "", errors.New("restore target cannot be the filesystem root")
	}
	markerName := "." + base + restoreMarkerSuffix
	if len(markerName) > 255 {
		return "", errors.New("restore target name is too long for its required sibling marker")
	}
	return filepath.Join(filepath.Dir(targetDir), markerName), nil
}

type markerScanDirectory interface {
	ReadDir(int) ([]os.DirEntry, error)
	Close() error
}

type markerScanFilesystem struct {
	lstat   func(string) (os.FileInfo, error)
	stat    func(string) (os.FileInfo, error)
	openDir func(string) (markerScanDirectory, error)
}

func operatingSystemMarkerScan() markerScanFilesystem {
	return markerScanFilesystem{
		lstat: os.Lstat,
		stat:  os.Stat,
		openDir: func(path string) (markerScanDirectory, error) {
			return os.Open(path)
		},
	}
}

// RefuseIncompleteRestore returns ErrIncompleteRestore when the exact sibling
// marker for dataDir exists. When dataDir already exists, it also scans a
// bounded number of sibling entries and resolves every restore marker's target
// name. This catches case-folded and alternate-path spellings that identify the
// same directory. Callers must refuse startup rather than deleting or repairing
// a marker automatically.
func RefuseIncompleteRestore(dataDir string) error {
	return refuseIncompleteRestoreWith(dataDir, operatingSystemMarkerScan(), maxMarkerScanEntries)
}

func refuseIncompleteRestoreWith(dataDir string, filesystem markerScanFilesystem, scanLimit int) error {
	marker, err := RestoreMarkerPath(dataDir)
	if err != nil {
		return err
	}
	if filesystem.lstat == nil || filesystem.stat == nil || filesystem.openDir == nil || scanLimit < 1 {
		return errors.New("restore marker scanner is unavailable")
	}
	info, err := filesystem.lstat(marker)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("%w: unsafe marker exists at %s", ErrIncompleteRestore, marker)
		}
		return fmt.Errorf("%w: marker exists at %s; run mesh-backup finalize-restore after verifying the restored data", ErrIncompleteRestore, marker)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect restore marker: %w", err)
	}
	targetInfo, err := filesystem.stat(dataDir)
	if errors.Is(err, os.ErrNotExist) {
		// There is no inode against which alternate sibling names can be
		// compared. The exact marker check above still fences a not-yet-created
		// restore target.
		return nil
	}
	if err != nil {
		return fmt.Errorf("resolve restore target for marker scan: %w", err)
	}
	return scanSiblingRestoreMarkers(filepath.Dir(dataDir), targetInfo, filesystem, scanLimit)
}

func scanSiblingRestoreMarkers(parent string, targetInfo os.FileInfo, filesystem markerScanFilesystem, scanLimit int) (result error) {
	directory, err := filesystem.openDir(parent)
	if err != nil {
		return fmt.Errorf("open restore marker parent for bounded scan: %w", err)
	}
	defer func() {
		if closeErr := directory.Close(); closeErr != nil {
			result = errors.Join(result, fmt.Errorf("close restore marker parent scan: %w", closeErr))
		}
	}()

	scanned := 0
	for {
		entries, readErr := directory.ReadDir(markerScanBatchSize)
		if len(entries) == 0 && readErr == nil {
			return errors.New("restore marker parent scan made no progress")
		}
		for _, entry := range entries {
			scanned++
			if scanned > scanLimit {
				return fmt.Errorf("restore marker parent exceeds the bounded %d-entry startup scan", scanLimit)
			}
			base, ok := restoreTargetBaseFromMarker(entry.Name())
			if !ok {
				continue
			}
			candidate := filepath.Join(parent, base)
			candidateInfo, statErr := filesystem.stat(candidate)
			if errors.Is(statErr, os.ErrNotExist) {
				continue
			}
			if statErr != nil {
				return fmt.Errorf("resolve restore marker candidate %s: %w", candidate, statErr)
			}
			if os.SameFile(targetInfo, candidateInfo) {
				return fmt.Errorf("%w: sibling marker %s resolves to the requested data directory", ErrIncompleteRestore, filepath.Join(parent, entry.Name()))
			}
		}
		if errors.Is(readErr, io.EOF) {
			return nil
		}
		if readErr != nil {
			return fmt.Errorf("scan restore marker parent: %w", readErr)
		}
	}
}

func restoreTargetBaseFromMarker(name string) (string, bool) {
	if !strings.HasPrefix(name, ".") || !strings.HasSuffix(name, restoreMarkerSuffix) {
		return "", false
	}
	base := strings.TrimSuffix(strings.TrimPrefix(name, "."), restoreMarkerSuffix)
	if base == "" || base == "." || base == ".." || filepath.Base(base) != base {
		return "", false
	}
	return base, true
}

func encodeJSONLine(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

func decodeStrictJSON(raw []byte, value any) error {
	if len(raw) == 0 || raw[len(raw)-1] != '\n' || strings.ContainsRune(string(raw), '\r') {
		return errors.New("document must be canonical JSON followed by one LF")
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("document contains trailing JSON")
		}
		return err
	}
	canonical, err := encodeJSONLine(value)
	if err != nil {
		return err
	}
	if string(canonical) != string(raw) {
		return errors.New("document is not canonical JSON")
	}
	return nil
}
