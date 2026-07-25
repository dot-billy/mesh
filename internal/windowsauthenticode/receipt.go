package windowsauthenticode

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"
)

const (
	ReceiptSchema        = "mesh-windows-authenticode-receipt-v1"
	MaximumReceiptSize   = 32 << 10
	maximumReceiptAge    = 24 * time.Hour
	maximumReceiptFuture = 5 * time.Minute
)

type FileEvidence struct {
	CertificateSHA256 string `json:"certificate_sha256"`
	Path              string `json:"path"`
	Role              string `json:"role"`
	SHA256            string `json:"sha256"`
	SignerSPKISHA256  string `json:"signer_spki_sha256"`
	Size              int64  `json:"size"`
}

type Receipt struct {
	Architecture string         `json:"architecture"`
	Files        []FileEvidence `json:"files"`
	PolicySHA256 string         `json:"policy_sha256"`
	Schema       string         `json:"schema"`
	VerifiedAt   string         `json:"verified_at"`
}

type ArtifactIdentity struct {
	Path   string
	SHA256 string
	Size   int64
}

func EncodeReceipt(receipt Receipt) ([]byte, error) {
	if err := validateReceipt(receipt); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(receipt)
	if err != nil {
		return nil, fmt.Errorf("encode Windows Authenticode receipt: %w", err)
	}
	if len(raw)+1 > MaximumReceiptSize {
		return nil, errors.New("Windows Authenticode receipt exceeds its size bound")
	}
	return append(raw, '\n'), nil
}

func ParseReceipt(raw []byte) (Receipt, error) {
	if len(raw) < 2 || len(raw) > MaximumReceiptSize {
		return Receipt{}, errors.New("Windows Authenticode receipt is empty or oversized")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var receipt Receipt
	if err := decoder.Decode(&receipt); err != nil {
		return Receipt{}, fmt.Errorf("decode Windows Authenticode receipt: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Receipt{}, errors.New("Windows Authenticode receipt contains trailing data")
	}
	if err := validateReceipt(receipt); err != nil {
		return Receipt{}, err
	}
	canonical, err := EncodeReceipt(receipt)
	if err != nil {
		return Receipt{}, err
	}
	if !bytes.Equal(canonical, raw) {
		return Receipt{}, errors.New("Windows Authenticode receipt must be canonical compact JSON followed by one LF")
	}
	return receipt, nil
}

func (receipt Receipt) Match(now time.Time, policySHA256, arch string, artifacts []ArtifactIdentity) error {
	if err := validateReceipt(receipt); err != nil {
		return err
	}
	verifiedAt, _ := time.Parse(time.RFC3339, receipt.VerifiedAt)
	now = now.UTC()
	if now.IsZero() || verifiedAt.After(now.Add(maximumReceiptFuture)) {
		return errors.New("Windows Authenticode receipt verification time is in the future")
	}
	if now.Sub(verifiedAt) > maximumReceiptAge {
		return errors.New("Windows Authenticode receipt is older than 24 hours")
	}
	if receipt.PolicySHA256 != policySHA256 || receipt.Architecture != arch {
		return errors.New("Windows Authenticode receipt policy or architecture differs from the release")
	}
	wanted := append([]ArtifactIdentity(nil), artifacts...)
	sort.Slice(wanted, func(left, right int) bool { return wanted[left].Path < wanted[right].Path })
	if len(wanted) != len(receipt.Files) {
		return errors.New("Windows Authenticode receipt artifact set is incomplete")
	}
	for index, artifact := range wanted {
		file := receipt.Files[index]
		if artifact.Path != file.Path || artifact.Size != file.Size || artifact.SHA256 != file.SHA256 {
			return fmt.Errorf("Windows Authenticode receipt differs from signed artifact %q", artifact.Path)
		}
	}
	return nil
}

func validateReceipt(receipt Receipt) error {
	if receipt.Schema != ReceiptSchema || (receipt.Architecture != "amd64" && receipt.Architecture != "arm64") ||
		!digestPattern.MatchString(receipt.PolicySHA256) {
		return errors.New("Windows Authenticode receipt schema, architecture, or policy is invalid")
	}
	verifiedAt, err := time.Parse(time.RFC3339, receipt.VerifiedAt)
	if err != nil || verifiedAt.UTC().Format(time.RFC3339) != receipt.VerifiedAt {
		return errors.New("Windows Authenticode receipt time is not canonical UTC RFC3339")
	}
	expected := []struct {
		path string
		role string
	}{
		{path: "bin/dist/windows/wintun/bin/" + receipt.Architecture + "/wintun.dll", role: WintunSignerRole},
		{path: "bin/meshctl.exe", role: MeshSignerRole},
		{path: "bin/nebula-cert.exe", role: MeshSignerRole},
		{path: "bin/nebula.exe", role: MeshSignerRole},
	}
	if len(receipt.Files) != len(expected) {
		return errors.New("Windows Authenticode receipt must contain exactly four signed files")
	}
	meshSPKI, meshCertificate := "", ""
	for index, file := range receipt.Files {
		want := expected[index]
		if file.Path != want.path || file.Role != want.role || file.Size < 512 || file.Size > 132<<20 ||
			!digestPattern.MatchString(file.SHA256) || !digestPattern.MatchString(file.SignerSPKISHA256) ||
			!digestPattern.MatchString(file.CertificateSHA256) {
			return fmt.Errorf("Windows Authenticode receipt file %d is invalid or unordered", index)
		}
		if file.Role == MeshSignerRole {
			if meshSPKI == "" {
				meshSPKI, meshCertificate = file.SignerSPKISHA256, file.CertificateSHA256
			} else if file.SignerSPKISHA256 != meshSPKI || file.CertificateSHA256 != meshCertificate {
				return errors.New("Windows Mesh executables do not share one Authenticode signer certificate")
			}
		}
	}
	return nil
}
