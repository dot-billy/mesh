package darwinbundle

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"mesh/internal/darwincodesign"
)

func TestBuildSignedBindsExactMachOReplacementAndNativeReceipt(t *testing.T) {
	arch := "arm64"
	unsignedContents := signedFixtureContents(t, arch)
	policy := signedFixturePolicy(arch, unsignedContents)
	directory := t.TempDir()
	unsignedPath := filepath.Join(directory, "unsigned.tar")
	if _, err := buildWithPolicy(fixtureBuildOptions(arch, unsignedPath), policy, unsignedContents); err != nil {
		t.Fatal(err)
	}
	finalContents := make(map[string][]byte, len(unsignedContents))
	for name, content := range unsignedContents {
		finalContents[name] = append([]byte(nil), content...)
	}
	for _, name := range []string{"bin/meshctl", "bin/nebula", "bin/nebula-cert"} {
		finalContents[name] = syntheticCMSReplacement(t, finalContents[name])
	}
	_, codesignPolicy, err := darwincodesign.EncodePolicy(darwincodesign.PolicySpec{
		TeamID: "AB12CD34EF", MeshInstallIdentifier: "io.mesh.node.mesh-install",
		MeshctlIdentifier: "io.mesh.node.meshctl",
		NebulaIdentifier:  "io.mesh.node.nebula", NebulaCertIdentifier: "io.mesh.node.nebula-cert",
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)
	receipt := darwincodesign.Receipt{
		Schema: darwincodesign.ReceiptSchema, Architecture: arch,
		PolicySHA256: codesignPolicy.SHA256, TeamID: codesignPolicy.TeamID,
		VerifiedAt: now.Format(time.RFC3339),
		Files: []darwincodesign.FileEvidence{{
			Identifier: codesignPolicy.MeshInstallIdentifier,
			Path:       "mesh-install",
			Role:       darwincodesign.MeshInstallRole,
			SHA256:     strings.Repeat("0", 64),
			Size:       900,
		}},
	}
	inputPaths := make(map[string]string)
	for _, item := range []struct {
		path       string
		role       string
		identifier string
	}{
		{path: "bin/meshctl", role: darwincodesign.MeshctlRole, identifier: codesignPolicy.MeshctlIdentifier},
		{path: "bin/nebula", role: darwincodesign.NebulaRole, identifier: codesignPolicy.NebulaIdentifier},
		{path: "bin/nebula-cert", role: darwincodesign.NebulaCertRole, identifier: codesignPolicy.NebulaCertIdentifier},
	} {
		path := filepath.Join(directory, strings.ReplaceAll(item.path, "/", "-"))
		if err := os.WriteFile(path, finalContents[item.path], 0o555); err != nil {
			t.Fatal(err)
		}
		inputPaths[item.path] = path
		receipt.Files = append(receipt.Files, darwincodesign.FileEvidence{
			Identifier: item.identifier, Path: item.path, Role: item.role,
			SHA256: sha256Hex(finalContents[item.path]), Size: int64(len(finalContents[item.path])),
		})
	}
	receiptRaw, err := darwincodesign.EncodeReceipt(receipt)
	if err != nil {
		t.Fatal(err)
	}
	receiptPath := filepath.Join(directory, "codesign-receipt.json")
	if err := os.WriteFile(receiptPath, receiptRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	options := SignedBuildOptions{
		UnsignedBundlePath: unsignedPath, SignedMeshctlPath: inputPaths["bin/meshctl"],
		SignedNebulaPath: inputPaths["bin/nebula"], SignedNebulaCertPath: inputPaths["bin/nebula-cert"],
		CodesignReceiptPath: receiptPath, ExpectedPolicySHA256: codesignPolicy.SHA256,
		OutputPath: filepath.Join(directory, "signed.tar"),
	}
	resolver := func(string) (bundlePolicy, error) { return signedFixturePolicy(arch, unsignedContents), nil }
	result, err := buildSignedWithPolicy(options, now, codesignPolicy, resolver)
	if err != nil {
		t.Fatal(err)
	}
	if result.Package.Schema != SignedSchema {
		t.Fatalf("signed schema=%q", result.Package.Schema)
	}
	stage := filepath.Join(directory, "inspect")
	if err := os.Mkdir(stage, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { removeSignedInspectionStage(stage) })
	raw, err := os.ReadFile(result.OutputPath)
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(stage)
	if err != nil {
		t.Fatal(err)
	}
	inspection, inspectErr := inspectAndStageCandidateWithPolicy(raw, root, resolver)
	closeErr := root.Close()
	err = errors.Join(inspectErr, closeErr)
	if err != nil || inspection.Package.Schema != SignedSchema {
		t.Fatalf("inspect final signed Darwin bundle: schema=%q error=%v", inspection.Package.Schema, err)
	}
	tampered := append([]byte(nil), finalContents["bin/nebula"]...)
	tampered[4096] ^= 1
	tamperedPath := filepath.Join(directory, "tampered-nebula")
	if err := os.WriteFile(tamperedPath, tampered, 0o555); err != nil {
		t.Fatal(err)
	}
	options.SignedNebulaPath = tamperedPath
	options.OutputPath = filepath.Join(directory, "rejected.tar")
	if _, err := buildSignedWithPolicy(options, now, codesignPolicy, resolver); err == nil {
		t.Fatal("signed Darwin executable with code-region drift was accepted")
	}
}

func signedFixtureContents(t *testing.T, arch string) map[string][]byte {
	t.Helper()
	contents := fixtureContents(t, arch, fixtureIdentity())
	meshctl := contents["bin/meshctl"]
	contents["bin/nebula"] = append([]byte(nil), meshctl...)
	contents["bin/nebula-cert"] = append([]byte(nil), meshctl...)
	return contents
}

func signedFixturePolicy(arch string, contents map[string][]byte) bundlePolicy {
	policy := fixturePolicy(arch, contents)
	for _, name := range []string{"bin/meshctl", "bin/nebula", "bin/nebula-cert"} {
		policy.expectation[name] = contentExpectation{archiveMode: 0o555, kind: kindMeshctl}
	}
	return policy
}

func syntheticCMSReplacement(t *testing.T, source []byte) []byte {
	t.Helper()
	envelope, err := darwincodesign.InspectMachOSignature(source)
	if err != nil {
		t.Fatal(err)
	}
	if envelope.Size < 64 {
		t.Fatal("fixture linker signature is too small")
	}
	result := append([]byte(nil), source...)
	raw := result[envelope.Offset:]
	clear(raw)
	big := binary.BigEndian
	big.PutUint32(raw[0:4], 0xfade0cc0)
	big.PutUint32(raw[4:8], uint32(len(raw)))
	big.PutUint32(raw[8:12], 2)
	const codeOffset = 28
	cmsOffset := len(raw) - 9
	big.PutUint32(raw[12:16], 0)
	big.PutUint32(raw[16:20], codeOffset)
	big.PutUint32(raw[20:24], 0x10000)
	big.PutUint32(raw[24:28], uint32(cmsOffset))
	big.PutUint32(raw[codeOffset:codeOffset+4], 0xfade0c02)
	big.PutUint32(raw[codeOffset+4:codeOffset+8], uint32(cmsOffset-codeOffset))
	big.PutUint32(raw[codeOffset+12:codeOffset+16], 0x10000)
	big.PutUint32(raw[cmsOffset:cmsOffset+4], 0xfade0b01)
	big.PutUint32(raw[cmsOffset+4:cmsOffset+8], 9)
	raw[cmsOffset+8] = 1
	return result
}
