package originimage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"

	releasetrust "mesh/internal/release"
)

const (
	DefaultTimeout = 5 * time.Minute
	MaxTimeout     = time.Hour
	maxCosignJSON  = 1 << 20
	maxSignatures  = 128
)

type Config struct {
	Image      string
	PublicKey  string
	CosignPath string
	Timeout    time.Duration
}

type Runner interface {
	Verify(context.Context, string, string, string) ([]byte, error)
}

type ExecRunner struct{}

func (ExecRunner) Verify(ctx context.Context, cosignPath, keyPath, image string) ([]byte, error) {
	var output limitedBuffer
	output.maximum = maxCosignJSON
	command := exec.CommandContext(ctx, cosignPath,
		"verify", "--key", keyPath, "--check-claims=true", "--output", "json", image)
	command.Env = os.Environ()
	command.Stdin = bytes.NewReader(nil)
	command.Stdout = &output
	command.Stderr = io.Discard
	if err := command.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("Cosign verification deadline: %w", ctx.Err())
		}
		return nil, errors.New("Cosign rejected the exact origin image or could not complete verification")
	}
	if output.overflow {
		return nil, fmt.Errorf("Cosign verification output exceeded %d bytes", maxCosignJSON)
	}
	return output.Bytes(), nil
}

type limitedBuffer struct {
	bytes.Buffer
	maximum  int
	overflow bool
}

func (writer *limitedBuffer) Write(raw []byte) (int, error) {
	remaining := writer.maximum - writer.Len()
	if remaining <= 0 {
		writer.overflow = true
		return len(raw), nil
	}
	if len(raw) > remaining {
		writer.overflow = true
		_, _ = writer.Buffer.Write(raw[:remaining])
		return len(raw), nil
	}
	return writer.Buffer.Write(raw)
}

func Verify(ctx context.Context, config Config, clock func() time.Time, runner Runner) (Receipt, error) {
	if ctx == nil || clock == nil || runner == nil {
		return Receipt{}, errors.New("origin image verification requires context, clock, and runner")
	}
	reference, err := ParseReference(config.Image)
	if err != nil {
		return Receipt{}, err
	}
	if config.Timeout <= 0 || config.Timeout > MaxTimeout {
		return Receipt{}, fmt.Errorf("origin image verification timeout must be positive and no greater than %s", MaxTimeout)
	}
	publicKey, publicKeyDigest, err := loadPublicKey(config.PublicKey)
	if err != nil {
		return Receipt{}, err
	}
	cosignDigestBefore, err := hashCosign(config.CosignPath)
	if err != nil {
		return Receipt{}, err
	}
	keySnapshot, cleanup, err := writePublicKeySnapshot(publicKey)
	if err != nil {
		return Receipt{}, err
	}
	defer cleanup()
	deadlineContext, cancel := context.WithTimeout(ctx, config.Timeout)
	defer cancel()
	verificationJSON, err := runner.Verify(deadlineContext, config.CosignPath, keySnapshot, reference.Canonical)
	if err != nil {
		return Receipt{}, err
	}
	signatureCount, err := verifiedSignatureCount(verificationJSON, reference.Digest)
	if err != nil {
		return Receipt{}, err
	}
	cosignDigestAfter, err := hashCosign(config.CosignPath)
	if err != nil {
		return Receipt{}, err
	}
	if cosignDigestBefore != cosignDigestAfter {
		return Receipt{}, errors.New("Cosign executable changed during verification")
	}
	verifiedAt := clock()
	if verifiedAt.Location() != time.UTC || verifiedAt.Format(time.RFC3339Nano) == "" {
		return Receipt{}, errors.New("origin image verification clock must return UTC")
	}
	receipt := Receipt{
		Schema:          ReceiptSchema,
		Image:           reference.Canonical,
		ManifestSHA256:  reference.Digest,
		PublicKeySHA256: publicKeyDigest,
		CosignSHA256:    cosignDigestAfter,
		VerifiedAt:      verifiedAt.Format(time.RFC3339Nano),
		SignatureCount:  signatureCount,
	}
	if err := validateReceipt(receipt); err != nil {
		return Receipt{}, err
	}
	return receipt, nil
}

type cosignPayload struct {
	Critical struct {
		Image struct {
			DockerManifestDigest string `json:"docker-manifest-digest"`
		} `json:"image"`
		Type string `json:"type"`
	} `json:"critical"`
}

func verifiedSignatureCount(raw []byte, digest string) (int, error) {
	if len(raw) == 0 || len(raw) > maxCosignJSON || !json.Valid(raw) {
		return 0, errors.New("Cosign returned invalid or oversized verification JSON")
	}
	if err := releasetrust.ValidateStrictJSON(raw); err != nil {
		return 0, errors.New("Cosign returned ambiguous verification JSON")
	}
	var payloads []cosignPayload
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) > 0 && trimmed[0] == '{' {
		var payload cosignPayload
		if err := json.Unmarshal(trimmed, &payload); err != nil {
			return 0, errors.New("Cosign returned an invalid signature payload")
		}
		payloads = []cosignPayload{payload}
	} else if err := json.Unmarshal(trimmed, &payloads); err != nil {
		return 0, errors.New("Cosign returned an invalid signature payload list")
	}
	if len(payloads) < 1 || len(payloads) > maxSignatures {
		return 0, fmt.Errorf("Cosign must return between 1 and %d verified signature payloads", maxSignatures)
	}
	expected := "sha256:" + digest
	for _, payload := range payloads {
		if payload.Critical.Type != "cosign container image signature" ||
			(payload.Critical.Image.DockerManifestDigest != expected && payload.Critical.Image.DockerManifestDigest != digest) {
			return 0, errors.New("Cosign verification payload does not bind the requested image digest")
		}
	}
	return len(payloads), nil
}
