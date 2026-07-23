package windowsbundle

import (
	"bytes"
	"encoding/asn1"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"mesh/internal/windowsauthenticode"
)

func TestBuildSignedBindsExactReconstructionAndNativeReceipt(t *testing.T) {
	arch := "amd64"
	unsignedContents := fixtureContents(t, arch, fixtureIdentity())
	unsignedContents["bin/nebula.exe"] = append([]byte(nil), unsignedContents["bin/meshctl.exe"]...)
	unsignedContents["bin/nebula-cert.exe"] = append([]byte(nil), unsignedContents["bin/meshctl.exe"]...)
	wintun := append([]byte(nil), unsignedContents["bin/meshctl.exe"]...)
	setPEDLLCharacteristic(t, wintun)
	unsignedContents["bin/dist/windows/wintun/bin/amd64/wintun.dll"] = syntheticSignedPE(t, wintun)
	unsignedPolicy := fixturePolicy(arch, unsignedContents)

	unsignedPath := filepath.Join(t.TempDir(), "unsigned.tar")
	if _, err := buildWithPolicy(fixtureBuildOptions(arch, unsignedPath), unsignedPolicy, unsignedContents); err != nil {
		t.Fatal(err)
	}
	signedContents := cloneContentMap(unsignedContents)
	for _, name := range []string{"bin/meshctl.exe", "bin/nebula-cert.exe", "bin/nebula.exe"} {
		signedContents[name] = syntheticSignedPE(t, unsignedContents[name])
	}
	signedPolicy := fixturePolicy(arch, signedContents)
	now := time.Date(2026, 7, 21, 20, 0, 0, 0, time.UTC)
	policySHA := strings.Repeat("a", 64)
	directory := t.TempDir()
	options := writeSignedBuildInputs(t, directory, unsignedPath, signedContents, receiptForSignedContents(t, arch, policySHA, now, signedContents))

	resolver := func(policy bundlePolicy) candidatePolicyResolver {
		return func(wantArch string) (bundlePolicy, error) {
			if wantArch != arch {
				t.Fatalf("policy requested for %q", wantArch)
			}
			return policy, nil
		}
	}
	first, err := buildSignedWithPolicies(options, now, resolver(unsignedPolicy), resolver(signedPolicy))
	if err != nil {
		t.Fatal(err)
	}
	if first.Package.Schema != SignedSchema {
		t.Fatalf("final schema = %q", first.Package.Schema)
	}
	raw, err := os.ReadFile(first.OutputPath)
	if err != nil {
		t.Fatal(err)
	}
	inspection, _, expanded, err := inspectCandidateArchiveWithPolicy(raw, resolver(signedPolicy))
	if err != nil {
		t.Fatal(err)
	}
	if inspection.Package.Schema != SignedSchema {
		t.Fatalf("inspected schema = %q", inspection.Package.Schema)
	}
	for name, want := range signedContents {
		if !bytes.Equal(expanded[name], want) {
			t.Fatalf("final signed payload %q changed", name)
		}
	}

	secondOptions := options
	secondOptions.OutputPath = filepath.Join(directory, "second.tar")
	second, err := buildSignedWithPolicies(secondOptions, now, resolver(unsignedPolicy), resolver(signedPolicy))
	if err != nil {
		t.Fatal(err)
	}
	secondRaw, err := os.ReadFile(second.OutputPath)
	if err != nil {
		t.Fatal(err)
	}
	if first.SHA256 != second.SHA256 || !bytes.Equal(raw, secondRaw) {
		t.Fatal("equivalent signed Windows inputs did not produce one deterministic bundle")
	}

	tampered := append([]byte(nil), signedContents["bin/meshctl.exe"]...)
	tampered[len(tampered)-8] ^= 1
	tamperedPath := filepath.Join(directory, "tampered-meshctl.exe")
	if err := os.WriteFile(tamperedPath, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	tamperedOptions := options
	tamperedOptions.SignedMeshctlPath = tamperedPath
	tamperedOptions.OutputPath = filepath.Join(directory, "must-not-exist.tar")
	if _, err := buildSignedWithPolicies(tamperedOptions, now, resolver(unsignedPolicy), resolver(signedPolicy)); err == nil {
		t.Fatal("signed PE differing from the native receipt was accepted")
	}
	if _, err := os.Lstat(tamperedOptions.OutputPath); !os.IsNotExist(err) {
		t.Fatalf("rejected signed build published output: %v", err)
	}
}

func writeSignedBuildInputs(t *testing.T, directory, unsignedPath string, contents map[string][]byte, receipt []byte) SignedBuildOptions {
	t.Helper()
	paths := make(map[string]string, 3)
	for _, name := range []string{"bin/meshctl.exe", "bin/nebula-cert.exe", "bin/nebula.exe"} {
		path := filepath.Join(directory, filepath.Base(name))
		if err := os.WriteFile(path, contents[name], 0o600); err != nil {
			t.Fatal(err)
		}
		paths[name] = path
	}
	receiptPath := filepath.Join(directory, "authenticode.json")
	if err := os.WriteFile(receiptPath, receipt, 0o600); err != nil {
		t.Fatal(err)
	}
	return SignedBuildOptions{
		UnsignedBundlePath: unsignedPath, SignedMeshctlPath: paths["bin/meshctl.exe"],
		SignedNebulaPath: paths["bin/nebula.exe"], SignedNebulaCertPath: paths["bin/nebula-cert.exe"],
		AuthenticodeReceiptPath: receiptPath, ExpectedPolicySHA256: strings.Repeat("a", 64),
		OutputPath: filepath.Join(directory, "final.tar"),
	}
}

func receiptForSignedContents(t *testing.T, arch, policySHA string, now time.Time, contents map[string][]byte) []byte {
	t.Helper()
	paths := []string{
		"bin/dist/windows/wintun/bin/" + arch + "/wintun.dll",
		"bin/meshctl.exe", "bin/nebula-cert.exe", "bin/nebula.exe",
	}
	receipt := windowsauthenticode.Receipt{
		Architecture: arch, PolicySHA256: policySHA,
		Schema: windowsauthenticode.ReceiptSchema, VerifiedAt: now.Format(time.RFC3339),
	}
	for _, name := range paths {
		role := windowsauthenticode.MeshSignerRole
		spki, certificate := strings.Repeat("b", 64), strings.Repeat("c", 64)
		if name == paths[0] {
			role = windowsauthenticode.WintunSignerRole
			spki, certificate = strings.Repeat("d", 64), strings.Repeat("e", 64)
		}
		receipt.Files = append(receipt.Files, windowsauthenticode.FileEvidence{
			CertificateSHA256: certificate, Path: name, Role: role,
			SHA256: sha256Hex(contents[name]), SignerSPKISHA256: spki, Size: int64(len(contents[name])),
		})
	}
	raw, err := windowsauthenticode.EncodeReceipt(receipt)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func syntheticSignedPE(t *testing.T, unsigned []byte) []byte {
	t.Helper()
	peOffset := int(binary.LittleEndian.Uint32(unsigned[0x3c:0x40]))
	optionalOffset := peOffset + 24
	directoryOffset := optionalOffset + 112 + 4*8
	checksumOffset := optionalOffset + 64
	type contentInfo struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue `asn1:"tag:0,explicit"`
	}
	body, err := asn1.Marshal(struct{ Value int }{Value: 7})
	if err != nil {
		t.Fatal(err)
	}
	pkcs7, err := asn1.Marshal(contentInfo{
		ContentType: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2},
		Content:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: body},
	})
	if err != nil {
		t.Fatal(err)
	}
	certificateLength := 8 + len(pkcs7)
	certificateSize := (certificateLength + 7) &^ 7
	certificateOffset := (len(unsigned) + 7) &^ 7
	signed := make([]byte, certificateOffset+certificateSize)
	copy(signed, unsigned)
	binary.LittleEndian.PutUint32(signed[checksumOffset:checksumOffset+4], 0x12345678)
	binary.LittleEndian.PutUint32(signed[directoryOffset:directoryOffset+4], uint32(certificateOffset))
	binary.LittleEndian.PutUint32(signed[directoryOffset+4:directoryOffset+8], uint32(certificateSize))
	binary.LittleEndian.PutUint32(signed[certificateOffset:certificateOffset+4], uint32(certificateLength))
	binary.LittleEndian.PutUint16(signed[certificateOffset+4:certificateOffset+6], 0x0200)
	binary.LittleEndian.PutUint16(signed[certificateOffset+6:certificateOffset+8], 0x0002)
	copy(signed[certificateOffset+8:], pkcs7)
	return signed
}

func cloneContentMap(input map[string][]byte) map[string][]byte {
	result := make(map[string][]byte, len(input))
	for name, content := range input {
		result[name] = append([]byte(nil), content...)
	}
	return result
}
