package releaseorigin

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"mesh/internal/onlinerelease"
)

type storedObject struct {
	metadata Object
	identity fileIdentity
	file     *os.File
	etag     string
}

type Store struct {
	mu      sync.RWMutex
	objects map[string]*storedObject
	closed  bool
}

func Open(root string, indexRaw []byte) (*Store, error) {
	if err := validateRoot(root); err != nil {
		return nil, err
	}
	index, err := Parse(indexRaw)
	if err != nil {
		return nil, err
	}
	store := &Store{objects: make(map[string]*storedObject, len(index.Objects))}
	closeOnFailure := true
	defer func() {
		if closeOnFailure {
			_ = store.Close()
		}
	}()
	for _, metadata := range index.Objects {
		file, identity, err := openStableObject(root, metadata.Path)
		if err != nil {
			return nil, err
		}
		if identity.size != metadata.Size {
			_ = file.Close()
			return nil, fmt.Errorf("release origin object %q size is %d, index requires %d", metadata.Path, identity.size, metadata.Size)
		}
		digest, err := hashObject(file, identity)
		if err != nil {
			_ = file.Close()
			return nil, fmt.Errorf("release origin object %q: %w", metadata.Path, err)
		}
		if hex.EncodeToString(digest[:]) != metadata.SHA256 {
			_ = file.Close()
			return nil, fmt.Errorf("release origin object %q SHA-256 differs from its index", metadata.Path)
		}
		if metadata.Cache == CacheChannel {
			raw, readErr := io.ReadAll(io.NewSectionReader(file, 0, identity.size))
			if readErr != nil {
				_ = file.Close()
				return nil, fmt.Errorf("read channel object %q: %w", metadata.Path, readErr)
			}
			if _, parseErr := onlinerelease.Parse(raw); parseErr != nil {
				_ = file.Close()
				return nil, fmt.Errorf("channel object %q is not a canonical online release bundle: %w", metadata.Path, parseErr)
			}
		}
		store.objects[metadata.Path] = &storedObject{
			metadata: metadata,
			identity: identity,
			file:     file,
			etag:     `"sha256:` + metadata.SHA256 + `"`,
		}
	}
	closeOnFailure = false
	return store, nil
}

func OpenFiles(root, indexPath string) (*Store, error) {
	raw, err := readStableIndex(indexPath)
	if err != nil {
		return nil, err
	}
	return Open(root, raw)
}

func readStableIndex(path string) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("release origin index must be a clean absolute path")
	}
	if err := rejectSymlinkPath(path, false); err != nil {
		return nil, err
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect release origin index: %w", err)
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || before.Size() < 1 || before.Size() > MaxIndexSize || !singleLink(before) {
		return nil, errors.New("release origin index must be one bounded single-link regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open release origin index: %w", err)
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !sameObjectFile(before, after) {
		return nil, errors.New("release origin index changed while opening")
	}
	raw, err := io.ReadAll(io.LimitReader(file, MaxIndexSize+1))
	if err != nil || len(raw) < 1 || len(raw) > MaxIndexSize {
		return nil, errors.New("read bounded release origin index")
	}
	final, err := file.Stat()
	if err != nil || !sameObjectFile(after, final) {
		return nil, errors.New("release origin index changed while reading")
	}
	return raw, nil
}

func (store *Store) CheckReadiness() error {
	if store == nil {
		return errors.New("release origin store is nil")
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	if store.closed {
		return errors.New("release origin store is closed")
	}
	for _, object := range store.objects {
		current, err := object.file.Stat()
		if err != nil || !sameObjectFile(object.identity.info, current) {
			return fmt.Errorf("release origin object %q changed after startup", object.metadata.Path)
		}
	}
	return nil
}

func (store *Store) Close() error {
	if store == nil {
		return nil
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.closed {
		return nil
	}
	store.closed = true
	var result error
	for _, object := range store.objects {
		result = errors.Join(result, object.file.Close())
	}
	return result
}
