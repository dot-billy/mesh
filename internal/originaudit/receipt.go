// Package originaudit verifies that one public HTTPS release-origin route
// serves the exact locally inspected content-addressed generation.
package originaudit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	releasetrust "mesh/internal/release"
	"mesh/internal/releaseorigin"
)

const (
	ReceiptSchema  = "mesh-release-origin-audit-v1"
	MaxReceiptSize = 4096
)

type Receipt struct {
	Schema              string `json:"schema"`
	Generation          string `json:"generation"`
	IndexSHA256         string `json:"index_sha256"`
	Origin              string `json:"origin"`
	CertificateSHA256   string `json:"certificate_sha256"`
	CertificateNotAfter string `json:"certificate_not_after"`
	CheckedAt           string `json:"checked_at"`
	ObjectCount         int    `json:"object_count"`
	TotalSize           int64  `json:"total_size"`
	RequestCount        int    `json:"request_count"`
}

func EncodeReceipt(receipt Receipt) ([]byte, error) {
	if err := validateReceipt(receipt); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(receipt)
	if err != nil {
		return nil, fmt.Errorf("encode release origin audit receipt: %w", err)
	}
	raw = append(raw, '\n')
	if len(raw) > MaxReceiptSize {
		return nil, fmt.Errorf("release origin audit receipt exceeds %d bytes", MaxReceiptSize)
	}
	return raw, nil
}

func ParseReceipt(raw []byte) (Receipt, error) {
	if len(raw) == 0 || len(raw) > MaxReceiptSize {
		return Receipt{}, fmt.Errorf("release origin audit receipt size must be between 1 and %d bytes", MaxReceiptSize)
	}
	if err := releasetrust.ValidateStrictJSON(raw); err != nil {
		return Receipt{}, fmt.Errorf("invalid release origin audit receipt JSON: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var receipt Receipt
	if err := decoder.Decode(&receipt); err != nil {
		return Receipt{}, fmt.Errorf("decode release origin audit receipt: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return Receipt{}, errors.New("release origin audit receipt contains trailing content")
	}
	if err := validateReceipt(receipt); err != nil {
		return Receipt{}, err
	}
	canonical, err := EncodeReceipt(receipt)
	if err != nil {
		return Receipt{}, err
	}
	if !bytes.Equal(raw, canonical) {
		return Receipt{}, errors.New("release origin audit receipt must be canonical compact JSON followed by one LF")
	}
	return receipt, nil
}

func validateReceipt(receipt Receipt) error {
	if receipt.Schema != ReceiptSchema {
		return fmt.Errorf("unsupported release origin audit receipt schema %q", receipt.Schema)
	}
	if !validSHA256(receipt.Generation) || receipt.Generation != receipt.IndexSHA256 {
		return errors.New("release origin audit generation and index SHA-256 must be the same 64 lowercase hexadecimal characters")
	}
	if _, err := canonicalOrigin(receipt.Origin); err != nil {
		return err
	}
	if !validSHA256(receipt.CertificateSHA256) {
		return errors.New("release origin audit certificate SHA-256 must be 64 lowercase hexadecimal characters")
	}
	notAfter, err := parseCanonicalUTC(receipt.CertificateNotAfter, "certificate expiry")
	if err != nil {
		return err
	}
	checkedAt, err := parseCanonicalUTC(receipt.CheckedAt, "check time")
	if err != nil {
		return err
	}
	if !checkedAt.Before(notAfter) {
		return errors.New("release origin audit check time must be before certificate expiry")
	}
	if receipt.ObjectCount < 1 || receipt.ObjectCount > releaseorigin.MaxObjects {
		return fmt.Errorf("release origin audit object count must be between 1 and %d", releaseorigin.MaxObjects)
	}
	if receipt.TotalSize < 1 {
		return errors.New("release origin audit total size must be positive")
	}
	if receipt.RequestCount != 2*receipt.ObjectCount+3 {
		return errors.New("release origin audit request count is inconsistent")
	}
	return nil
}

func validSHA256(value string) bool {
	digest, err := hex.DecodeString(value)
	return err == nil && len(digest) == sha256.Size && hex.EncodeToString(digest) == value
}

func parseCanonicalUTC(value, label string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.Location() != time.UTC || parsed.Format(time.RFC3339Nano) != value {
		return time.Time{}, fmt.Errorf("release origin audit %s must be canonical UTC RFC3339", label)
	}
	return parsed, nil
}
