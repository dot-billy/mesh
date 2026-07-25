package windowsauthenticode

import (
	"crypto/sha256"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
)

const (
	peSignature                  = 0x00004550
	pe32PlusMagic                = 0x020b
	peCertificateDirectoryIndex  = 4
	winCertificateRevision20     = 0x0200
	winCertificateTypePKCSSigned = 0x0002
	maximumCertificateTableSize  = 4 << 20
)

var pkcs7SignedDataOID = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}

type PEEnvelope struct {
	CertificateOffset int
	CertificateSize   int
	CertificateSHA256 string
	ChecksumOffset    int
	DirectoryOffset   int
}

type pkcs7ContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"tag:0,explicit"`
}

// InspectPEEnvelope applies the portable structural portion of the production
// Authenticode contract. Windows remains responsible for file-digest, signer,
// timestamp, chain, revocation, EKU, and role-pin verification.
func InspectPEEnvelope(content []byte) (PEEnvelope, error) {
	if len(content) < 512 || len(content) > 132<<20 {
		return PEEnvelope{}, errors.New("Windows Authenticode PE size is outside its bound")
	}
	if content[0] != 'M' || content[1] != 'Z' {
		return PEEnvelope{}, errors.New("Windows Authenticode target has no DOS header")
	}
	peOffset64 := uint64(binary.LittleEndian.Uint32(content[0x3c:0x40]))
	if peOffset64 < 0x40 || peOffset64 > uint64(len(content)-24) {
		return PEEnvelope{}, errors.New("Windows Authenticode PE header offset is invalid")
	}
	peOffset := int(peOffset64)
	if binary.LittleEndian.Uint32(content[peOffset:peOffset+4]) != peSignature {
		return PEEnvelope{}, errors.New("Windows Authenticode PE signature is invalid")
	}
	optionalSize := int(binary.LittleEndian.Uint16(content[peOffset+20 : peOffset+22]))
	optionalOffset := peOffset + 24
	if optionalSize < 152 || optionalOffset > len(content)-optionalSize ||
		binary.LittleEndian.Uint16(content[optionalOffset:optionalOffset+2]) != pe32PlusMagic {
		return PEEnvelope{}, errors.New("Windows Authenticode target is not a bounded PE32+ image")
	}
	numberOfDirectories := binary.LittleEndian.Uint32(content[optionalOffset+108 : optionalOffset+112])
	if numberOfDirectories <= peCertificateDirectoryIndex {
		return PEEnvelope{}, errors.New("Windows Authenticode PE has no certificate directory")
	}
	checksumOffset := optionalOffset + 64
	directoryOffset := optionalOffset + 112 + peCertificateDirectoryIndex*8
	if directoryOffset > optionalOffset+optionalSize-8 {
		return PEEnvelope{}, errors.New("Windows Authenticode certificate directory is outside the optional header")
	}
	certificateOffset64 := uint64(binary.LittleEndian.Uint32(content[directoryOffset : directoryOffset+4]))
	certificateSize64 := uint64(binary.LittleEndian.Uint32(content[directoryOffset+4 : directoryOffset+8]))
	if certificateOffset64 == 0 || certificateOffset64%8 != 0 || certificateSize64 < 8 ||
		certificateSize64 > maximumCertificateTableSize || certificateOffset64 > uint64(len(content)) ||
		certificateSize64 != uint64(len(content))-certificateOffset64 {
		return PEEnvelope{}, errors.New("Windows Authenticode certificate table is absent, unaligned, oversized, or not the sole file overlay")
	}
	certificateOffset := int(certificateOffset64)
	certificateSize := int(certificateSize64)
	declaredLength := int(binary.LittleEndian.Uint32(content[certificateOffset : certificateOffset+4]))
	if declaredLength < 9 || declaredLength > certificateSize || alignEight(declaredLength) != certificateSize ||
		binary.LittleEndian.Uint16(content[certificateOffset+4:certificateOffset+6]) != winCertificateRevision20 ||
		binary.LittleEndian.Uint16(content[certificateOffset+6:certificateOffset+8]) != winCertificateTypePKCSSigned {
		return PEEnvelope{}, errors.New("Windows Authenticode certificate table is not one exact revision-2 PKCS signed-data entry")
	}
	for _, padding := range content[certificateOffset+declaredLength : certificateOffset+certificateSize] {
		if padding != 0 {
			return PEEnvelope{}, errors.New("Windows Authenticode certificate-table padding is not zero")
		}
	}
	pkcs7 := content[certificateOffset+8 : certificateOffset+declaredLength]
	var info pkcs7ContentInfo
	rest, err := asn1.Unmarshal(pkcs7, &info)
	if err != nil || len(rest) != 0 || !info.ContentType.Equal(pkcs7SignedDataOID) || len(info.Content.Bytes) == 0 {
		return PEEnvelope{}, errors.New("Windows Authenticode certificate entry is not one DER PKCS#7 signed-data object")
	}
	digest := sha256.Sum256(content[certificateOffset : certificateOffset+declaredLength])
	return PEEnvelope{
		CertificateOffset: certificateOffset, CertificateSize: certificateSize,
		CertificateSHA256: hex.EncodeToString(digest[:]), ChecksumOffset: checksumOffset,
		DirectoryOffset: directoryOffset,
	}, nil
}

// ReconstructUnsignedPE removes only the exact certificate overlay and the
// two PE fields Authenticode signing is allowed to rewrite. expectedSize and
// expectedSHA256 come from the independently reviewed reproducible output lock.
func ReconstructUnsignedPE(content []byte, expectedSize int64, expectedSHA256 string) ([]byte, PEEnvelope, error) {
	if expectedSize < 512 || expectedSize > int64(len(content)) || !digestPattern.MatchString(expectedSHA256) {
		return nil, PEEnvelope{}, errors.New("expected unsigned Windows PE identity is invalid")
	}
	envelope, err := InspectPEEnvelope(content)
	if err != nil {
		return nil, PEEnvelope{}, err
	}
	if int64(envelope.CertificateOffset) < expectedSize || int64(envelope.CertificateOffset)-expectedSize > 7 {
		return nil, PEEnvelope{}, errors.New("Windows Authenticode certificate overlay is not adjacent to the expected unsigned PE")
	}
	for _, padding := range content[expectedSize:envelope.CertificateOffset] {
		if padding != 0 {
			return nil, PEEnvelope{}, errors.New("Windows Authenticode pre-certificate alignment padding is not zero")
		}
	}
	unsigned := append([]byte(nil), content[:expectedSize]...)
	if envelope.ChecksumOffset > len(unsigned)-4 || envelope.DirectoryOffset > len(unsigned)-8 {
		return nil, PEEnvelope{}, errors.New("Windows Authenticode mutable PE fields are outside the expected unsigned image")
	}
	clear(unsigned[envelope.ChecksumOffset : envelope.ChecksumOffset+4])
	clear(unsigned[envelope.DirectoryOffset : envelope.DirectoryOffset+8])
	digest := sha256.Sum256(unsigned)
	actual := hex.EncodeToString(digest[:])
	if actual != expectedSHA256 {
		return nil, PEEnvelope{}, fmt.Errorf("reconstructed unsigned Windows PE SHA-256 %s differs from output lock", actual)
	}
	return unsigned, envelope, nil
}

func alignEight(value int) int { return (value + 7) &^ 7 }
