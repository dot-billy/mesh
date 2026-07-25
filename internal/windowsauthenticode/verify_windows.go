//go:build windows

package windowsauthenticode

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	wssGetSecondarySignatureCount = 0x00000002
	cmsgSignerCountParam          = 5
	cmsgSignerInfoParam           = 6
	sha256OID                     = "2.16.840.1.101.3.4.2.1"
)

var (
	crypt32DLL          = windows.NewLazySystemDLL("crypt32.dll")
	cryptMsgGetParamAPI = crypt32DLL.NewProc("CryptMsgGetParam")
	cryptMsgCloseAPI    = crypt32DLL.NewProc("CryptMsgClose")
)

type cryptAttribute struct {
	ObjectID   *byte
	ValueCount uint32
	Values     *windows.CryptAttrBlob
}

type cryptAttributes struct {
	Count      uint32
	Attributes *cryptAttribute
}

type cmsgSignerInfo struct {
	Version                 uint32
	Issuer                  windows.CertNameBlob
	SerialNumber            windows.CryptIntegerBlob
	HashAlgorithm           windows.CryptAlgorithmIdentifier
	HashEncryptionAlgorithm windows.CryptAlgorithmIdentifier
	EncryptedHash           windows.CryptDataBlob
	AuthenticatedAttributes cryptAttributes
	UnauthenticatedAttrs    cryptAttributes
}

type Verification struct {
	PolicySHA256      string `json:"policy_sha256"`
	Role              string `json:"role"`
	SignerSPKISHA256  string `json:"signer_spki_sha256"`
	CertificateSHA256 string `json:"certificate_sha256"`
	Subject           string `json:"subject"`
	Issuer            string `json:"issuer"`
	SerialNumber      string `json:"serial_number"`
	NotBefore         string `json:"not_before"`
	NotAfter          string `json:"not_after"`
}

// VerifyFile requires the compiled production publisher policy, Windows'
// Authenticode file digest and chain policy, online whole-chain revocation,
// SHA-256, one embedded signer, and the exact role-specific SPKI pin.
func VerifyFile(path, role string) (Verification, error) {
	policy, err := LoadPolicy()
	if err != nil {
		return Verification{}, err
	}
	return verifyFileUsingPolicy(path, role, policy)
}

func verifyFileUsingPolicy(path, role string, policy Policy) (result Verification, returnErr error) {
	if role != MeshSignerRole && role != WintunSignerRole {
		return result, errors.New("Windows Authenticode signer role is unsupported")
	}
	if !cleanLocalWindowsPath(path) {
		return result, errors.New("Windows Authenticode path must be clean, absolute, local, and non-root")
	}
	before, err := os.Lstat(path)
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || before.Size() < 1 {
		return result, errors.Join(err, errors.New("Windows Authenticode target is not a nonempty real regular file"))
	}
	file, err := os.Open(path)
	if err != nil {
		return result, err
	}
	defer func() { returnErr = errors.Join(returnErr, file.Close()) }()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return result, errors.Join(err, errors.New("Windows Authenticode target changed while opening"))
	}
	path16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return result, err
	}
	settings := windows.WinTrustSignatureSettings{
		Size:  uint32(unsafe.Sizeof(windows.WinTrustSignatureSettings{})),
		Flags: wssGetSecondarySignatureCount,
	}
	fileInfo := windows.WinTrustFileInfo{
		Size: uint32(unsafe.Sizeof(windows.WinTrustFileInfo{})), FilePath: path16,
		File: windows.Handle(file.Fd()),
	}
	trust := windows.WinTrustData{
		Size: uint32(unsafe.Sizeof(windows.WinTrustData{})), UIChoice: windows.WTD_UI_NONE,
		RevocationChecks: windows.WTD_REVOKE_WHOLECHAIN, UnionChoice: windows.WTD_CHOICE_FILE,
		FileOrCatalogOrBlobOrSgnrOrCert: unsafe.Pointer(&fileInfo), StateAction: windows.WTD_STATEACTION_VERIFY,
		ProvFlags: windows.WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT | windows.WTD_LIFETIME_SIGNING_FLAG | windows.WTD_DISABLE_MD2_MD4,
		UIContext: windows.WTD_UICONTEXT_INSTALL, SignatureSettings: &settings,
	}
	verifyErr := windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, &trust)
	trust.StateAction = windows.WTD_STATEACTION_CLOSE
	closeTrustErr := windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, &trust)
	if verifyErr != nil || closeTrustErr != nil {
		return result, errors.Join(fmt.Errorf("verify Windows Authenticode trust: %w", verifyErr), closeTrustErr)
	}
	if settings.SecondarySigs != 0 || settings.VerifiedSigIndex != 0 {
		return result, errors.New("Windows Authenticode target must contain exactly one primary signature and no secondary signatures")
	}
	certificate, hashOID, err := signerCertificate(path16)
	if err != nil {
		return result, err
	}
	if hashOID != sha256OID {
		return result, fmt.Errorf("Windows Authenticode signer digest algorithm %q is not SHA-256", hashOID)
	}
	if certificate.KeyUsage&x509.KeyUsageDigitalSignature == 0 || !hasCodeSigningUsage(certificate) {
		return result, errors.New("Windows Authenticode signer certificate lacks exact code-signing usage")
	}
	spki := sha256.Sum256(certificate.RawSubjectPublicKeyInfo)
	spkiSHA256 := hex.EncodeToString(spki[:])
	if !policy.Allows(role, spkiSHA256) {
		return result, errors.New("Windows Authenticode signer public key is not authorized for this role")
	}
	certificateDigest := sha256.Sum256(certificate.Raw)
	result = Verification{
		PolicySHA256: policy.SHA256, Role: role, SignerSPKISHA256: spkiSHA256,
		CertificateSHA256: hex.EncodeToString(certificateDigest[:]),
		Subject:           certificate.Subject.String(), Issuer: certificate.Issuer.String(),
		SerialNumber: strings.ToLower(certificate.SerialNumber.Text(16)),
		NotBefore:    certificate.NotBefore.UTC().Format("2006-01-02T15:04:05Z"),
		NotAfter:     certificate.NotAfter.UTC().Format("2006-01-02T15:04:05Z"),
	}
	openedAfter, openErr := file.Stat()
	pathAfter, pathErr := os.Lstat(path)
	if openErr != nil || pathErr != nil || !os.SameFile(opened, openedAfter) || !os.SameFile(opened, pathAfter) || opened.Size() != openedAfter.Size() {
		return Verification{}, errors.Join(openErr, pathErr, errors.New("Windows Authenticode target changed during verification"))
	}
	runtime.KeepAlive(path16)
	return result, nil
}

func signerCertificate(path16 *uint16) (certificate *x509.Certificate, hashOID string, returnErr error) {
	var encodingType, contentType, formatType uint32
	var store, message windows.Handle
	if err := windows.CryptQueryObject(
		windows.CERT_QUERY_OBJECT_FILE, unsafe.Pointer(path16),
		windows.CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
		windows.CERT_QUERY_FORMAT_FLAG_BINARY, 0,
		&encodingType, &contentType, &formatType, &store, &message, nil,
	); err != nil {
		return nil, "", fmt.Errorf("query embedded Windows Authenticode signature: %w", err)
	}
	defer func() {
		returnErr = errors.Join(returnErr, closeCryptMessage(message), windows.CertCloseStore(store, 0))
	}()
	if contentType != windows.CERT_QUERY_CONTENT_PKCS7_SIGNED_EMBED || formatType != windows.CERT_QUERY_FORMAT_BINARY ||
		encodingType&(windows.X509_ASN_ENCODING|windows.PKCS_7_ASN_ENCODING) != (windows.X509_ASN_ENCODING|windows.PKCS_7_ASN_ENCODING) {
		return nil, "", errors.New("Windows Authenticode signature content or encoding is unexpected")
	}
	var signerCount uint32
	signerCountSize := uint32(unsafe.Sizeof(signerCount))
	if err := cryptMsgGetParam(message, cmsgSignerCountParam, 0, unsafe.Pointer(&signerCount), &signerCountSize); err != nil {
		return nil, "", err
	}
	if signerCount != 1 || signerCountSize != uint32(unsafe.Sizeof(signerCount)) {
		return nil, "", errors.New("Windows Authenticode PKCS#7 must contain exactly one signer")
	}
	var signerSize uint32
	if err := cryptMsgGetParam(message, cmsgSignerInfoParam, 0, nil, &signerSize); err != nil {
		return nil, "", err
	}
	if signerSize < uint32(unsafe.Sizeof(cmsgSignerInfo{})) || signerSize > 64<<10 {
		return nil, "", errors.New("Windows Authenticode signer information is outside its bound")
	}
	buffer := make([]byte, signerSize)
	if err := cryptMsgGetParam(message, cmsgSignerInfoParam, 0, unsafe.Pointer(&buffer[0]), &signerSize); err != nil {
		return nil, "", err
	}
	signer := (*cmsgSignerInfo)(unsafe.Pointer(&buffer[0]))
	oid, err := boundedCString(signer.HashAlgorithm.ObjId, 128)
	if err != nil {
		return nil, "", err
	}
	info := windows.CertInfo{Issuer: signer.Issuer, SerialNumber: signer.SerialNumber}
	context, err := windows.CertFindCertificateInStore(
		store, windows.X509_ASN_ENCODING|windows.PKCS_7_ASN_ENCODING, 0,
		windows.CERT_FIND_SUBJECT_CERT, unsafe.Pointer(&info), nil,
	)
	if err != nil {
		return nil, "", fmt.Errorf("find Windows Authenticode signer certificate: %w", err)
	}
	defer func() { returnErr = errors.Join(returnErr, windows.CertFreeCertificateContext(context)) }()
	if context.Length == 0 || context.Length > 64<<10 || context.EncodedCert == nil {
		return nil, "", errors.New("Windows Authenticode signer certificate is empty or oversized")
	}
	raw := append([]byte(nil), unsafe.Slice(context.EncodedCert, context.Length)...)
	parsed, err := x509.ParseCertificate(raw)
	if err != nil {
		return nil, "", fmt.Errorf("parse Windows Authenticode signer certificate: %w", err)
	}
	runtime.KeepAlive(buffer)
	return parsed, oid, nil
}

func cryptMsgGetParam(message windows.Handle, parameter, index uint32, output unsafe.Pointer, size *uint32) error {
	result, _, callErr := cryptMsgGetParamAPI.Call(
		uintptr(message), uintptr(parameter), uintptr(index), uintptr(output), uintptr(unsafe.Pointer(size)),
	)
	if result == 0 {
		if callErr != nil && !errors.Is(callErr, windows.ERROR_SUCCESS) {
			return fmt.Errorf("read Windows Authenticode signer information: %w", callErr)
		}
		return errors.New("read Windows Authenticode signer information")
	}
	return nil
}

func closeCryptMessage(message windows.Handle) error {
	if message == 0 {
		return nil
	}
	result, _, callErr := cryptMsgCloseAPI.Call(uintptr(message))
	if result == 0 {
		if callErr != nil && !errors.Is(callErr, windows.ERROR_SUCCESS) {
			return callErr
		}
		return errors.New("close Windows Authenticode message")
	}
	return nil
}

func boundedCString(value *byte, maximum int) (string, error) {
	if value == nil || maximum < 1 {
		return "", errors.New("Windows Authenticode object identifier is absent")
	}
	bytes := unsafe.Slice(value, maximum)
	for index, character := range bytes {
		if character == 0 {
			if index == 0 {
				return "", errors.New("Windows Authenticode object identifier is empty")
			}
			return string(bytes[:index]), nil
		}
	}
	return "", errors.New("Windows Authenticode object identifier exceeds its bound")
}

func hasCodeSigningUsage(certificate *x509.Certificate) bool {
	if certificate == nil {
		return false
	}
	for _, usage := range certificate.ExtKeyUsage {
		if usage == x509.ExtKeyUsageCodeSigning {
			return true
		}
	}
	return false
}

func cleanLocalWindowsPath(value string) bool {
	if !filepath.IsAbs(value) || filepath.Clean(value) != value || filepath.Dir(value) == value || strings.HasPrefix(value, `\\`) {
		return false
	}
	volume := filepath.VolumeName(value)
	return len(volume) == 2 && volume[1] == ':'
}
