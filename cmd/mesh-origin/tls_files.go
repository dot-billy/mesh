package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const maximumTLSFileSize = 1 << 20

func loadOriginCertificate(certPath, keyPath string) (tls.Certificate, error) {
	certRaw, err := readStableTLSFile("TLS certificate", certPath, false)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyRaw, err := readStableTLSFile("TLS private key", keyPath, true)
	if err != nil {
		return tls.Certificate{}, err
	}
	defer clearBytes(keyRaw)
	certificate, err := tls.X509KeyPair(certRaw, keyRaw)
	if err != nil {
		return tls.Certificate{}, errors.New("parse TLS certificate and private key")
	}
	return certificate, nil
}

func readStableTLSFile(role, path string, private bool) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, fmt.Errorf("%s path must be clean and absolute", role)
	}
	for current := filepath.Dir(path); ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return nil, fmt.Errorf("%s path component %q is not a real directory", role, current)
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect %s: %w", role, err)
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || before.Size() < 1 || before.Size() > maximumTLSFileSize || !originTLSFileAllowed(before, private) {
		return nil, fmt.Errorf("%s must be a bounded, single-link regular file with safe ownership and permissions", role)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", role, err)
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() || before.Mode() != after.Mode() || !before.ModTime().Equal(after.ModTime()) || !originTLSFileAllowed(after, private) {
		return nil, fmt.Errorf("%s changed while opening", role)
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximumTLSFileSize+1))
	if err != nil || len(raw) < 1 || len(raw) > maximumTLSFileSize {
		return nil, fmt.Errorf("read bounded %s", role)
	}
	final, err := file.Stat()
	if err != nil || !os.SameFile(after, final) || after.Size() != final.Size() || after.Mode() != final.Mode() || !after.ModTime().Equal(final.ModTime()) || !originTLSFileAllowed(final, private) {
		return nil, fmt.Errorf("%s changed while reading", role)
	}
	return raw, nil
}

func clearBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
