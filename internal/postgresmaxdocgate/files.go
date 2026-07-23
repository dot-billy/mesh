//go:build linux && postgresmaxdocgate

package postgresmaxdocgate

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

func LoadFixtureMetadata(path string) (FixtureMetadata, error) {
	raw, err := readRegularFile(path, 1<<20, false)
	if err != nil {
		return FixtureMetadata{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var metadata FixtureMetadata
	if err := decoder.Decode(&metadata); err != nil {
		return FixtureMetadata{}, errors.New("decode maximum-document fixture metadata failed")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return FixtureMetadata{}, errors.New("maximum-document fixture metadata contains trailing data")
	}
	if err := validateFixtureMetadata(metadata); err != nil {
		return FixtureMetadata{}, err
	}
	return metadata, nil
}

func loadFixtureCredentials(metadata FixtureMetadata) ([]byte, string, error) {
	masterRaw, err := readRegularFile(metadata.Paths.MasterKey, 128, true)
	if err != nil {
		return nil, "", err
	}
	masterText := string(bytes.TrimSpace(masterRaw))
	clear(masterRaw)
	masterKey, err := base64.RawURLEncoding.DecodeString(masterText)
	if err != nil || len(masterKey) != 32 || base64.RawURLEncoding.EncodeToString(masterKey) != masterText {
		clear(masterKey)
		return nil, "", errors.New("maximum-document master key is invalid")
	}
	adminRaw, err := readRegularFile(metadata.Paths.AdminToken, 4097, true)
	if err != nil {
		clear(masterKey)
		return nil, "", err
	}
	adminToken := string(bytes.TrimSpace(adminRaw))
	clear(adminRaw)
	if len(adminToken) < 32 || len(adminToken) > 4096 {
		clear(masterKey)
		return nil, "", errors.New("maximum-document administrator token is invalid")
	}
	for index := range len(adminToken) {
		if adminToken[index] < 0x21 || adminToken[index] > 0x7e {
			clear(masterKey)
			return nil, "", errors.New("maximum-document administrator token is invalid")
		}
	}
	return masterKey, adminToken, nil
}

func readRegularFile(path string, maximum int64, private bool) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) {
		return nil, errors.New("maximum-document input path must be clean and absolute")
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maximum {
		return nil, errors.New("maximum-document input must be a bounded regular file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 {
		return nil, errors.New("maximum-document input ownership or link count is invalid")
	}
	if private && info.Mode().Perm() != 0o400 && info.Mode().Perm() != 0o600 {
		return nil, errors.New("maximum-document secret input must use mode 0400 or 0600")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("open maximum-document input failed")
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(raw)) != info.Size() {
		clear(raw)
		return nil, errors.New("read maximum-document input failed")
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(info, after) {
		clear(raw)
		return nil, errors.New("maximum-document input changed while reading")
	}
	return raw, nil
}

func verifyFileDigest(path string, expectedBytes int, expectedSHA string) error {
	raw, err := readAuthenticatedFixtureDocument(path, expectedBytes, expectedSHA)
	if err != nil {
		return err
	}
	clear(raw)
	return nil
}

func readAuthenticatedFixtureDocument(path string, expectedBytes int, expectedSHA string) ([]byte, error) {
	raw, err := readRegularFile(path, int64(expectedBytes), false)
	if err != nil {
		return nil, err
	}
	if len(raw) != expectedBytes {
		clear(raw)
		return nil, fmt.Errorf("maximum-document file size=%d, want %d", len(raw), expectedBytes)
	}
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != expectedSHA {
		clear(raw)
		return nil, errors.New("maximum-document file digest mismatch")
	}
	return raw, nil
}
