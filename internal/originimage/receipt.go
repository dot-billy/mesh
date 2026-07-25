package originimage

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	releasetrust "mesh/internal/release"
)

const (
	ReceiptSchema  = "mesh-origin-image-verification-v1"
	MaxReceiptSize = 4096
)

type Receipt struct {
	Schema          string `json:"schema"`
	Image           string `json:"image"`
	ManifestSHA256  string `json:"manifest_sha256"`
	PublicKeySHA256 string `json:"public_key_sha256"`
	CosignSHA256    string `json:"cosign_sha256"`
	VerifiedAt      string `json:"verified_at"`
	SignatureCount  int    `json:"signature_count"`
}

func EncodeReceipt(receipt Receipt) ([]byte, error) {
	if err := validateReceipt(receipt); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(receipt)
	if err != nil {
		return nil, fmt.Errorf("encode origin image verification receipt: %w", err)
	}
	raw = append(raw, '\n')
	if len(raw) > MaxReceiptSize {
		return nil, fmt.Errorf("origin image verification receipt exceeds %d bytes", MaxReceiptSize)
	}
	return raw, nil
}

func ParseReceipt(raw []byte) (Receipt, error) {
	if len(raw) == 0 || len(raw) > MaxReceiptSize {
		return Receipt{}, fmt.Errorf("origin image verification receipt size must be between 1 and %d bytes", MaxReceiptSize)
	}
	if err := releasetrust.ValidateStrictJSON(raw); err != nil {
		return Receipt{}, fmt.Errorf("invalid origin image verification receipt JSON: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var receipt Receipt
	if err := decoder.Decode(&receipt); err != nil {
		return Receipt{}, fmt.Errorf("decode origin image verification receipt: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return Receipt{}, errors.New("origin image verification receipt contains trailing content")
	}
	if err := validateReceipt(receipt); err != nil {
		return Receipt{}, err
	}
	canonical, err := EncodeReceipt(receipt)
	if err != nil {
		return Receipt{}, err
	}
	if !bytes.Equal(raw, canonical) {
		return Receipt{}, errors.New("origin image verification receipt must be canonical compact JSON followed by one LF")
	}
	return receipt, nil
}

func validateReceipt(receipt Receipt) error {
	if receipt.Schema != ReceiptSchema {
		return fmt.Errorf("unsupported origin image verification receipt schema %q", receipt.Schema)
	}
	reference, err := ParseReference(receipt.Image)
	if err != nil {
		return err
	}
	if reference.Digest != receipt.ManifestSHA256 || !validSHA256(receipt.PublicKeySHA256) || !validSHA256(receipt.CosignSHA256) {
		return errors.New("origin image verification receipt digests must be exact 64-character lowercase SHA-256 values")
	}
	parsed, err := time.Parse(time.RFC3339Nano, receipt.VerifiedAt)
	if err != nil || parsed.Location() != time.UTC || parsed.Format(time.RFC3339Nano) != receipt.VerifiedAt {
		return errors.New("origin image verification time must be canonical UTC RFC3339")
	}
	if receipt.SignatureCount < 1 || receipt.SignatureCount > maxSignatures {
		return fmt.Errorf("origin image signature count must be between 1 and %d", maxSignatures)
	}
	return nil
}

func validSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func WriteNewReceipt(path string, raw []byte) error {
	if _, err := ParseReceipt(raw); err != nil {
		return err
	}
	return writeNewReceipt(path, raw)
}
