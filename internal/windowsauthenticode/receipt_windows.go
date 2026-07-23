//go:build windows

package windowsauthenticode

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"time"
)

// CreateReceipt verifies every final PE through native Windows trust before
// and after a stable single-file hash. It emits no signing claim for a path
// that changes across either native verification boundary.
func CreateReceipt(arch string, paths map[string]string, now time.Time) (Receipt, error) {
	if arch != "amd64" && arch != "arm64" {
		return Receipt{}, errors.New("Windows Authenticode receipt architecture must be amd64 or arm64")
	}
	expectedRoles := map[string]string{
		"bin/dist/windows/wintun/bin/" + arch + "/wintun.dll": WintunSignerRole,
		"bin/meshctl.exe": MeshSignerRole, "bin/nebula-cert.exe": MeshSignerRole,
		"bin/nebula.exe": MeshSignerRole,
	}
	if len(paths) != len(expectedRoles) {
		return Receipt{}, errors.New("Windows Authenticode receipt requires exactly four final PE paths")
	}
	names := make([]string, 0, len(expectedRoles))
	for name := range expectedRoles {
		if paths[name] == "" {
			return Receipt{}, fmt.Errorf("Windows Authenticode receipt path %q is absent", name)
		}
		names = append(names, name)
	}
	sort.Strings(names)
	receipt := Receipt{Architecture: arch, Schema: ReceiptSchema}
	for _, name := range names {
		evidence, policySHA, err := verifyReceiptFile(paths[name], name, expectedRoles[name])
		if err != nil {
			return Receipt{}, err
		}
		if receipt.PolicySHA256 == "" {
			receipt.PolicySHA256 = policySHA
		} else if receipt.PolicySHA256 != policySHA {
			return Receipt{}, errors.New("Windows Authenticode verification policy changed between files")
		}
		receipt.Files = append(receipt.Files, evidence)
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if now.Location() != time.UTC || now.Nanosecond() != 0 {
		return Receipt{}, errors.New("Windows Authenticode receipt time must be whole-second UTC")
	}
	receipt.VerifiedAt = now.Format(time.RFC3339)
	if err := validateReceipt(receipt); err != nil {
		return Receipt{}, err
	}
	return receipt, nil
}

func verifyReceiptFile(path, name, role string) (FileEvidence, string, error) {
	first, err := VerifyFile(path, role)
	if err != nil {
		return FileEvidence{}, "", fmt.Errorf("verify %s before hashing: %w", name, err)
	}
	before, err := os.Lstat(path)
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || before.Size() < 512 || before.Size() > 132<<20 {
		return FileEvidence{}, "", errors.Join(err, fmt.Errorf("Windows Authenticode receipt path %q is not a bounded real PE", name))
	}
	file, err := os.Open(path)
	if err != nil {
		return FileEvidence{}, "", err
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		file.Close()
		return FileEvidence{}, "", errors.Join(err, fmt.Errorf("Windows Authenticode receipt path %q changed while opening", name))
	}
	hash := sha256.New()
	written, copyErr := io.Copy(hash, io.LimitReader(file, 132<<20+1))
	closeErr := file.Close()
	if copyErr != nil || closeErr != nil || written != opened.Size() {
		return FileEvidence{}, "", errors.Join(copyErr, closeErr, fmt.Errorf("Windows Authenticode receipt path %q changed while hashing", name))
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(opened, after) || after.Size() != opened.Size() {
		return FileEvidence{}, "", errors.Join(err, fmt.Errorf("Windows Authenticode receipt path %q changed after hashing", name))
	}
	second, err := VerifyFile(path, role)
	if err != nil || second != first {
		return FileEvidence{}, "", errors.Join(err, fmt.Errorf("Windows Authenticode receipt verification for %q changed across hashing", name))
	}
	final, err := os.Lstat(path)
	if err != nil || !os.SameFile(after, final) || final.Size() != after.Size() {
		return FileEvidence{}, "", errors.Join(err, fmt.Errorf("Windows Authenticode receipt path %q changed after final verification", name))
	}
	return FileEvidence{
		CertificateSHA256: first.CertificateSHA256, Path: name, Role: role,
		SHA256: hex.EncodeToString(hash.Sum(nil)), SignerSPKISHA256: first.SignerSPKISHA256,
		Size: written,
	}, first.PolicySHA256, nil
}
