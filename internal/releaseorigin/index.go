// Package releaseorigin implements the explicit, read-only object inventory
// served by a Mesh release origin. The origin is an untrusted courier: signed
// release metadata remains the authority for installer bytes.
package releaseorigin

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"mesh/internal/onlinerelease"
	releasetrust "mesh/internal/release"
)

const (
	Schema                = "mesh-release-origin-index-v1"
	CacheChannel          = "channel"
	CacheImmutable        = "immutable"
	MaxIndexSize          = 1 << 20
	MaxObjects            = 2048
	MaxObjectPathLength   = 512
	ContentTypeJSON       = "application/json"
	ContentTypeOctet      = "application/octet-stream"
	originIndexFileMode   = 0o644
	maximumObjectFileSize = releasetrust.MaxArtifactSize
)

type Index struct {
	Schema  string   `json:"schema"`
	Objects []Object `json:"objects"`
}

type Object struct {
	Path        string `json:"path"`
	Size        int64  `json:"size"`
	SHA256      string `json:"sha256"`
	ContentType string `json:"content_type"`
	Cache       string `json:"cache"`
}

func Encode(index Index) ([]byte, error) {
	if err := validateIndex(index); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(index)
	if err != nil {
		return nil, fmt.Errorf("encode release origin index: %w", err)
	}
	raw = append(raw, '\n')
	if len(raw) > MaxIndexSize {
		return nil, fmt.Errorf("release origin index exceeds %d bytes", MaxIndexSize)
	}
	return raw, nil
}

func Parse(raw []byte) (Index, error) {
	if len(raw) == 0 || len(raw) > MaxIndexSize {
		return Index{}, fmt.Errorf("release origin index size must be between 1 and %d bytes", MaxIndexSize)
	}
	if err := releasetrust.ValidateStrictJSON(raw); err != nil {
		return Index{}, fmt.Errorf("invalid release origin index JSON: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var index Index
	if err := decoder.Decode(&index); err != nil {
		return Index{}, fmt.Errorf("decode release origin index: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return Index{}, errors.New("release origin index contains trailing content")
	}
	if err := validateIndex(index); err != nil {
		return Index{}, err
	}
	canonical, err := Encode(index)
	if err != nil {
		return Index{}, err
	}
	if !bytes.Equal(raw, canonical) {
		return Index{}, errors.New("release origin index must be canonical compact JSON followed by one LF")
	}
	return cloneIndex(index), nil
}

// BuildIndex hashes a complete explicit allowlist. Paths are URL paths, never
// filesystem paths. Nothing in root is published unless it appears here.
func BuildIndex(root string, paths []string) (Index, error) {
	if err := validateRoot(root); err != nil {
		return Index{}, err
	}
	if len(paths) == 0 || len(paths) > MaxObjects {
		return Index{}, fmt.Errorf("release origin object count must be between 1 and %d", MaxObjects)
	}
	sorted := append([]string(nil), paths...)
	sort.Strings(sorted)
	objects := make([]Object, 0, len(sorted))
	for index, path := range sorted {
		if index > 0 && path == sorted[index-1] {
			return Index{}, fmt.Errorf("duplicate release origin object path %q", path)
		}
		if err := validateObjectPath(path); err != nil {
			return Index{}, err
		}
		contentType := ContentTypeOctet
		if strings.HasSuffix(path, ".json") {
			contentType = ContentTypeJSON
		}
		cache := CacheImmutable
		if strings.HasPrefix(path, "/channels/") {
			cache = CacheChannel
			if contentType != ContentTypeJSON {
				return Index{}, fmt.Errorf("channel object %q must be JSON", path)
			}
		}
		file, identity, err := openStableObject(root, path)
		if err != nil {
			return Index{}, err
		}
		if cache == CacheChannel {
			if identity.size > onlinerelease.MaxEncodedBundleSize {
				_ = file.Close()
				return Index{}, fmt.Errorf("channel object %q exceeds %d bytes", path, onlinerelease.MaxEncodedBundleSize)
			}
			channelRaw, readErr := io.ReadAll(io.NewSectionReader(file, 0, identity.size))
			if readErr != nil {
				_ = file.Close()
				return Index{}, fmt.Errorf("read channel object %q: %w", path, readErr)
			}
			if _, parseErr := onlinerelease.Parse(channelRaw); parseErr != nil {
				_ = file.Close()
				return Index{}, fmt.Errorf("channel object %q is not a canonical online release bundle: %w", path, parseErr)
			}
		}
		digest, hashErr := hashObject(file, identity)
		closeErr := file.Close()
		if hashErr != nil {
			return Index{}, hashErr
		}
		if closeErr != nil {
			return Index{}, fmt.Errorf("close release origin object %q: %w", path, closeErr)
		}
		objects = append(objects, Object{
			Path: path, Size: identity.size, SHA256: hex.EncodeToString(digest[:]),
			ContentType: contentType, Cache: cache,
		})
	}
	result := Index{Schema: Schema, Objects: objects}
	if err := validateIndex(result); err != nil {
		return Index{}, err
	}
	return result, nil
}

func validateIndex(index Index) error {
	if index.Schema != Schema {
		return fmt.Errorf("unsupported release origin index schema %q", index.Schema)
	}
	if len(index.Objects) == 0 || len(index.Objects) > MaxObjects {
		return fmt.Errorf("release origin object count must be between 1 and %d", MaxObjects)
	}
	previous := ""
	for position, object := range index.Objects {
		if err := validateObjectPath(object.Path); err != nil {
			return fmt.Errorf("release origin object %d: %w", position, err)
		}
		if previous != "" && object.Path <= previous {
			return errors.New("release origin objects must be strictly path-sorted without duplicates")
		}
		previous = object.Path
		if object.Size <= 0 || object.Size > maximumObjectFileSize {
			return fmt.Errorf("release origin object %q size must be between 1 and %d", object.Path, maximumObjectFileSize)
		}
		digest, err := hex.DecodeString(object.SHA256)
		if err != nil || len(digest) != sha256.Size || hex.EncodeToString(digest) != object.SHA256 {
			return fmt.Errorf("release origin object %q SHA-256 must be 64 lowercase hexadecimal characters", object.Path)
		}
		if object.ContentType != ContentTypeJSON && object.ContentType != ContentTypeOctet {
			return fmt.Errorf("release origin object %q has unsupported content type %q", object.Path, object.ContentType)
		}
		expectedContentType := ContentTypeOctet
		if strings.HasSuffix(object.Path, ".json") {
			expectedContentType = ContentTypeJSON
		}
		if object.ContentType != expectedContentType {
			return fmt.Errorf("release origin object %q content type does not match its path", object.Path)
		}
		expectedCache := CacheImmutable
		if strings.HasPrefix(object.Path, "/channels/") {
			expectedCache = CacheChannel
		}
		if object.Cache != expectedCache {
			return fmt.Errorf("release origin object %q cache policy must be %q", object.Path, expectedCache)
		}
		if object.Cache == CacheChannel && object.Size > onlinerelease.MaxEncodedBundleSize {
			return fmt.Errorf("release origin channel object %q exceeds %d bytes", object.Path, onlinerelease.MaxEncodedBundleSize)
		}
	}
	return nil
}

func validateObjectPath(path string) error {
	if len(path) < 2 || len(path) > MaxObjectPathLength || path[0] != '/' || strings.HasSuffix(path, "/") || strings.Contains(path, "//") {
		return fmt.Errorf("release origin object path %q is not one canonical absolute object path", path)
	}
	for _, component := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if component == "" || component == "." || component == ".." {
			return fmt.Errorf("release origin object path %q contains an invalid component", path)
		}
		for index := range len(component) {
			character := component[index]
			if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') &&
				(character < '0' || character > '9') && character != '.' && character != '_' && character != '-' {
				return fmt.Errorf("release origin object path %q contains an invalid character", path)
			}
		}
	}
	return nil
}

func cloneIndex(source Index) Index {
	return Index{Schema: source.Schema, Objects: append([]Object(nil), source.Objects...)}
}

func WriteNewIndex(path string, raw []byte) (returnErr error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("release origin index output must be a clean absolute path")
	}
	if _, err := Parse(raw); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, originIndexFileMode)
	if err != nil {
		return fmt.Errorf("create release origin index: %w", err)
	}
	remove := true
	closed := false
	defer func() {
		if !closed {
			returnErr = errors.Join(returnErr, file.Close())
		}
		if remove {
			returnErr = errors.Join(returnErr, os.Remove(path))
		}
	}()
	written, err := file.Write(raw)
	if err != nil {
		return fmt.Errorf("write release origin index: %w", err)
	}
	if written != len(raw) {
		return fmt.Errorf("write release origin index: wrote %d of %d bytes", written, len(raw))
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync release origin index: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close release origin index: %w", err)
	}
	closed = true
	remove = false
	return syncDirectory(filepath.Dir(path))
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
