package windowsauthenticode

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestReceiptCanonicalRoundTripAndMatching(t *testing.T) {
	receipt := testAuthenticodeReceipt("amd64")
	raw, err := EncodeReceipt(receipt)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseReceipt(raw)
	if err != nil {
		t.Fatal(err)
	}
	artifacts := make([]ArtifactIdentity, 0, len(parsed.Files))
	for _, file := range parsed.Files {
		artifacts = append(artifacts, ArtifactIdentity{Path: file.Path, SHA256: file.SHA256, Size: file.Size})
	}
	if err := parsed.Match(time.Date(2026, 7, 21, 18, 0, 0, 0, time.UTC), strings.Repeat("a", 64), "amd64", artifacts); err != nil {
		t.Fatal(err)
	}
	artifacts[0].Size++
	if err := parsed.Match(time.Date(2026, 7, 21, 18, 0, 0, 0, time.UTC), strings.Repeat("a", 64), "amd64", artifacts); err == nil {
		t.Fatal("receipt matched changed signed artifact")
	}
}

func TestReceiptRejectsPolicyCanonicalAndSignerDrift(t *testing.T) {
	valid, err := EncodeReceipt(testAuthenticodeReceipt("arm64"))
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func([]byte) []byte{
		"missing LF": func(raw []byte) []byte { return bytes.TrimSuffix(raw, []byte{'\n'}) },
		"unknown": func(raw []byte) []byte {
			var value map[string]any
			_ = json.Unmarshal(raw, &value)
			value["unknown"] = true
			encoded, _ := json.Marshal(value)
			return append(encoded, '\n')
		},
		"mixed Mesh signer": func(raw []byte) []byte {
			var receipt Receipt
			_ = json.Unmarshal(raw, &receipt)
			receipt.Files[2].SignerSPKISHA256 = strings.Repeat("9", 64)
			encoded, _ := json.Marshal(receipt)
			return append(encoded, '\n')
		},
		"weakened role": func(raw []byte) []byte {
			var receipt Receipt
			_ = json.Unmarshal(raw, &receipt)
			receipt.Files[1].Role = WintunSignerRole
			encoded, _ := json.Marshal(receipt)
			return append(encoded, '\n')
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseReceipt(mutate(bytes.Clone(valid))); err == nil {
				t.Fatal("drifted Authenticode receipt was accepted")
			}
		})
	}
}

func testAuthenticodeReceipt(arch string) Receipt {
	meshSPKI := strings.Repeat("b", 64)
	meshCert := strings.Repeat("c", 64)
	files := []FileEvidence{
		{CertificateSHA256: strings.Repeat("d", 64), Path: "bin/dist/windows/wintun/bin/" + arch + "/wintun.dll", Role: WintunSignerRole, SHA256: strings.Repeat("1", 64), SignerSPKISHA256: strings.Repeat("e", 64), Size: 1024},
		{CertificateSHA256: meshCert, Path: "bin/meshctl.exe", Role: MeshSignerRole, SHA256: strings.Repeat("2", 64), SignerSPKISHA256: meshSPKI, Size: 2048},
		{CertificateSHA256: meshCert, Path: "bin/nebula-cert.exe", Role: MeshSignerRole, SHA256: strings.Repeat("3", 64), SignerSPKISHA256: meshSPKI, Size: 3072},
		{CertificateSHA256: meshCert, Path: "bin/nebula.exe", Role: MeshSignerRole, SHA256: strings.Repeat("4", 64), SignerSPKISHA256: meshSPKI, Size: 4096},
	}
	return Receipt{
		Architecture: arch, Files: files, PolicySHA256: strings.Repeat("a", 64),
		Schema: ReceiptSchema, VerifiedAt: "2026-07-21T17:00:00Z",
	}
}
