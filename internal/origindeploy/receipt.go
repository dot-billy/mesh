// Package origindeploy binds one authenticated origin image and immutable
// generation to the hardened running Docker container selected by production
// Compose.
package origindeploy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

const (
	ReceiptSchema  = "mesh-origin-runtime-verification-v2"
	MaxReceiptSize = 8192
)

type Receipt struct {
	Schema                string `json:"schema"`
	ImageReceiptSHA256    string `json:"image_receipt_sha256"`
	SecurityReceiptSHA256 string `json:"security_receipt_sha256"`
	Image                 string `json:"image"`
	ManifestSHA256        string `json:"manifest_sha256"`
	ComposeSHA256         string `json:"compose_sha256"`
	Generation            string `json:"generation"`
	ContainerID           string `json:"container_id"`
	LocalImageID          string `json:"local_image_id"`
	DockerSHA256          string `json:"docker_sha256"`
	PublicURL             string `json:"public_url"`
	RuntimeUser           string `json:"runtime_user"`
	VerifiedAt            string `json:"verified_at"`
}

func EncodeReceipt(receipt Receipt) ([]byte, error) {
	if err := validateReceipt(receipt); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(receipt)
	if err != nil {
		return nil, fmt.Errorf("encode origin runtime verification receipt: %w", err)
	}
	raw = append(raw, '\n')
	if len(raw) > MaxReceiptSize {
		return nil, fmt.Errorf("origin runtime verification receipt exceeds %d bytes", MaxReceiptSize)
	}
	return raw, nil
}

func ParseReceipt(raw []byte) (Receipt, error) {
	if len(raw) == 0 || len(raw) > MaxReceiptSize {
		return Receipt{}, fmt.Errorf("origin runtime verification receipt size must be between 1 and %d bytes", MaxReceiptSize)
	}
	if err := validateStrictJSON(raw); err != nil {
		return Receipt{}, fmt.Errorf("invalid origin runtime verification receipt JSON: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var receipt Receipt
	if err := decoder.Decode(&receipt); err != nil {
		return Receipt{}, fmt.Errorf("decode origin runtime verification receipt: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return Receipt{}, errors.New("origin runtime verification receipt contains trailing content")
	}
	if err := validateReceipt(receipt); err != nil {
		return Receipt{}, err
	}
	canonical, err := EncodeReceipt(receipt)
	if err != nil {
		return Receipt{}, err
	}
	if !bytes.Equal(raw, canonical) {
		return Receipt{}, errors.New("origin runtime verification receipt must be canonical compact JSON followed by one LF")
	}
	return receipt, nil
}

func validateReceipt(receipt Receipt) error {
	if receipt.Schema != ReceiptSchema {
		return fmt.Errorf("unsupported origin runtime verification receipt schema %q", receipt.Schema)
	}
	for label, digest := range map[string]string{
		"image receipt": receipt.ImageReceiptSHA256, "security receipt": receipt.SecurityReceiptSHA256,
		"manifest": receipt.ManifestSHA256,
		"Compose":  receipt.ComposeSHA256, "generation": receipt.Generation,
		"container": receipt.ContainerID, "local image": receipt.LocalImageID,
		"Docker": receipt.DockerSHA256,
	} {
		if !validDigest(digest) {
			return fmt.Errorf("origin runtime %s identity must be 64 lowercase hexadecimal characters", label)
		}
	}
	image, err := parseImage(receipt.Image)
	if err != nil || image.digest != receipt.ManifestSHA256 {
		return errors.New("origin runtime image and manifest digest are inconsistent")
	}
	if _, err := parsePublicURL(receipt.PublicURL); err != nil {
		return err
	}
	if _, _, err := parseRuntimeUser(receipt.RuntimeUser); err != nil {
		return err
	}
	parsed, err := time.Parse(time.RFC3339Nano, receipt.VerifiedAt)
	if err != nil || parsed.Location() != time.UTC || parsed.Format(time.RFC3339Nano) != receipt.VerifiedAt {
		return errors.New("origin runtime verification time must be canonical UTC RFC3339")
	}
	return nil
}

func WriteNewReceipt(path string, raw []byte) error {
	if _, err := ParseReceipt(raw); err != nil {
		return err
	}
	return writeNewReceipt(path, raw)
}

func validDigest(value string) bool {
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
