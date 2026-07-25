//go:build !ios

package iosmobile

import "errors"

func loadOrCreatePrivateKey(_, _ string) ([]byte, error) {
	return nil, errors.New("iOS Keychain is unavailable")
}

func loadPrivateKey(_, _ string) ([]byte, error) {
	return nil, errors.New("iOS Keychain is unavailable")
}

func loadOrCreateSecret(_, _, _ string) ([]byte, error) {
	return nil, errors.New("iOS Keychain is unavailable")
}

func loadSecret(_, _, _ string) ([]byte, error) {
	return nil, errors.New("iOS Keychain is unavailable")
}

func replaceSecret(_, _, _ string, _ []byte) error {
	return errors.New("iOS Keychain is unavailable")
}

func deleteSecret(_, _, _ string) error {
	return errors.New("iOS Keychain is unavailable")
}
