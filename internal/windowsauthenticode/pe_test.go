package windowsauthenticode

import (
	"crypto/sha256"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestPEEnvelopeReconstructsExactUnsignedGoExecutable(t *testing.T) {
	unsigned := buildUnsignedWindowsTestPE(t)
	digest := sha256.Sum256(unsigned)
	signed := addSyntheticAuthenticodeEnvelope(t, unsigned)
	reconstructed, envelope, err := ReconstructUnsignedPE(signed, int64(len(unsigned)), hex.EncodeToString(digest[:]))
	if err != nil {
		t.Fatal(err)
	}
	if string(reconstructed) != string(unsigned) || envelope.CertificateOffset < len(unsigned) || envelope.CertificateSize < 8 || len(envelope.CertificateSHA256) != 64 {
		t.Fatal("signed Windows PE did not reconstruct to its exact unsigned bytes")
	}
}

func TestPEEnvelopeRejectsDrift(t *testing.T) {
	unsigned := buildUnsignedWindowsTestPE(t)
	digest := sha256.Sum256(unsigned)
	valid := addSyntheticAuthenticodeEnvelope(t, unsigned)
	mutations := map[string]func([]byte){
		"changed image": func(raw []byte) { raw[len(raw)/3] ^= 1 },
		"overlay byte":  func(raw []byte) { raw = append(raw, 0) },
		"directory size": func(raw []byte) {
			envelope, _ := InspectPEEnvelope(raw)
			binary.LittleEndian.PutUint32(raw[envelope.DirectoryOffset+4:envelope.DirectoryOffset+8], uint32(envelope.CertificateSize-1))
		},
		"certificate padding": func(raw []byte) { raw[len(raw)-1] = 1 },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			raw := append([]byte(nil), valid...)
			before := len(raw)
			mutate(raw)
			if name == "overlay byte" {
				raw = append(raw, 0)
			}
			if len(raw) < before {
				t.Fatal("invalid test mutation")
			}
			if _, _, err := ReconstructUnsignedPE(raw, int64(len(unsigned)), hex.EncodeToString(digest[:])); err == nil {
				t.Fatal("drifted signed Windows PE was accepted")
			}
		})
	}
}

func buildUnsignedWindowsTestPE(t *testing.T) []byte {
	t.Helper()
	output := filepath.Join(t.TempDir(), "mesh-bootstrap-verify.exe")
	command := exec.Command("go", "build", "-buildvcs=false", "-trimpath", "-o", output, "../../cmd/mesh-bootstrap-verify")
	command.Env = append(os.Environ(), "GOOS=windows", "GOARCH=amd64", "CGO_ENABLED=0")
	if raw, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build Windows test PE: %v\n%s", err, raw)
	}
	content, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	return content
}

func addSyntheticAuthenticodeEnvelope(t *testing.T, unsigned []byte) []byte {
	t.Helper()
	if len(unsigned) < 512 {
		t.Fatal("unsigned test PE is too small")
	}
	peOffset := int(binary.LittleEndian.Uint32(unsigned[0x3c:0x40]))
	optionalOffset := peOffset + 24
	directoryOffset := optionalOffset + 112 + peCertificateDirectoryIndex*8
	checksumOffset := optionalOffset + 64
	contentBody, err := asn1.Marshal(struct{ Value int }{Value: 7})
	if err != nil {
		t.Fatal(err)
	}
	pkcs7, err := asn1.Marshal(pkcs7ContentInfo{
		ContentType: pkcs7SignedDataOID,
		Content:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: contentBody},
	})
	if err != nil {
		t.Fatal(err)
	}
	certificateLength := 8 + len(pkcs7)
	certificateSize := alignEight(certificateLength)
	certificateOffset := alignEight(len(unsigned))
	signed := make([]byte, certificateOffset+certificateSize)
	copy(signed, unsigned)
	binary.LittleEndian.PutUint32(signed[checksumOffset:checksumOffset+4], 0x12345678)
	binary.LittleEndian.PutUint32(signed[directoryOffset:directoryOffset+4], uint32(certificateOffset))
	binary.LittleEndian.PutUint32(signed[directoryOffset+4:directoryOffset+8], uint32(certificateSize))
	binary.LittleEndian.PutUint32(signed[certificateOffset:certificateOffset+4], uint32(certificateLength))
	binary.LittleEndian.PutUint16(signed[certificateOffset+4:certificateOffset+6], winCertificateRevision20)
	binary.LittleEndian.PutUint16(signed[certificateOffset+6:certificateOffset+8], winCertificateTypePKCSSigned)
	copy(signed[certificateOffset+8:], pkcs7)
	return signed
}
