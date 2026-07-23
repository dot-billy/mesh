// Package kubeinit materializes Kubernetes projected secrets into the strict
// regular-file layout consumed by the Mesh control-plane container.
package kubeinit

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	maximumCredentialBytes = 4096
	maximumPolicyBytes     = 64 << 10
	maximumTLSBytes        = 1 << 20
	maximumDSNBytes        = 64 << 10
	finalDirectoryName     = "private"
	stageDirectoryName     = ".mesh-kube-init-stage"
)

// Options names the fixed projected-volume roots and the non-root identity
// that must own the materialized files. Optional source roots are empty when
// the corresponding feature is disabled.
type Options struct {
	CredentialsSourceDir string
	TLSSourceDir         string
	IdentitySourceDir    string
	PostgresSourceDir    string
	OutputRoot           string
	DataDir              string
	TLSServerName        string
	RuntimeUID           int
	RuntimeGID           int
}

// TLSOptions names the narrower TLS-only materialization used by the release
// origin. It deliberately has no credential, identity, storage, or signing-key
// inputs.
type TLSOptions struct {
	TLSSourceDir  string
	OutputRoot    string
	TLSServerName string
	RuntimeUID    int
	RuntimeGID    int
}

type materializedFile struct {
	name string
	mode os.FileMode
	raw  []byte
}

// Run validates every source before publishing one exact create-only private
// directory. A retry accepts only byte-identical already-published output.
func Run(options Options) error {
	if err := validateRuntime(options.RuntimeUID, options.RuntimeGID, options.TLSServerName); err != nil {
		return err
	}

	admin, err := readProjectedFile(options.CredentialsSourceDir, "admin.token", maximumCredentialBytes)
	if err != nil {
		return err
	}
	master, err := readProjectedFile(options.CredentialsSourceDir, "master.key", maximumCredentialBytes)
	if err != nil {
		return err
	}
	if err := validateAdminCredential(admin); err != nil {
		return err
	}
	if err := validateMasterKey(master); err != nil {
		return err
	}

	certificate, err := readProjectedFile(options.TLSSourceDir, "tls.crt", maximumTLSBytes)
	if err != nil {
		return err
	}
	privateKey, err := readProjectedFile(options.TLSSourceDir, "tls.key", maximumTLSBytes)
	if err != nil {
		return err
	}
	caBundle, err := readProjectedFile(options.TLSSourceDir, "ca.crt", maximumTLSBytes)
	if err != nil {
		return err
	}
	if err := validateTLSIdentity(certificate, privateKey, caBundle, options.TLSServerName); err != nil {
		return err
	}

	files := []materializedFile{
		{name: "admin.token", mode: 0o400, raw: admin},
		{name: "master.key", mode: 0o400, raw: master},
		{name: "server.crt", mode: 0o444, raw: certificate},
		{name: "server.key", mode: 0o400, raw: privateKey},
		{name: "ca.crt", mode: 0o444, raw: caBundle},
	}
	if options.IdentitySourceDir != "" {
		policy, readErr := readProjectedFile(options.IdentitySourceDir, "identity.json", maximumPolicyBytes)
		if readErr != nil {
			return readErr
		}
		if !json.Valid(policy) {
			return errors.New("identity.json is not valid JSON")
		}
		clientSecret, readErr := readProjectedFile(options.IdentitySourceDir, "oidc-client.secret", maximumCredentialBytes)
		if readErr != nil {
			return readErr
		}
		if err := validateCanonicalLine("oidc-client.secret", clientSecret, 1); err != nil {
			return err
		}
		files = append(files,
			materializedFile{name: "identity.json", mode: 0o400, raw: policy},
			materializedFile{name: "oidc-client.secret", mode: 0o400, raw: clientSecret},
		)
	}
	if options.PostgresSourceDir != "" {
		dsn, readErr := readProjectedFile(options.PostgresSourceDir, "postgres.dsn", maximumDSNBytes)
		if readErr != nil {
			return readErr
		}
		if err := validateCanonicalLine("postgres.dsn", dsn, 1); err != nil {
			return err
		}
		files = append(files, materializedFile{name: "postgres.dsn", mode: 0o400, raw: dsn})
	}

	if err := publish(options.OutputRoot, files, options.RuntimeUID, options.RuntimeGID); err != nil {
		return err
	}
	if options.DataDir != "" {
		if err := prepareDataDirectory(options.DataDir, options.RuntimeUID, options.RuntimeGID); err != nil {
			return err
		}
	}
	return nil
}

// RunTLS materializes one validated Kubernetes TLS projection into the strict
// owner-private regular-file layout consumed by mesh-origin. A byte-identical
// retry is accepted; changed or additional output is rejected.
func RunTLS(options TLSOptions) error {
	if err := validateRuntime(options.RuntimeUID, options.RuntimeGID, options.TLSServerName); err != nil {
		return err
	}
	certificate, err := readProjectedFile(options.TLSSourceDir, "tls.crt", maximumTLSBytes)
	if err != nil {
		return err
	}
	privateKey, err := readProjectedFile(options.TLSSourceDir, "tls.key", maximumTLSBytes)
	if err != nil {
		return err
	}
	defer clear(privateKey)
	caBundle, err := readProjectedFile(options.TLSSourceDir, "ca.crt", maximumTLSBytes)
	if err != nil {
		return err
	}
	if err := validateTLSIdentity(certificate, privateKey, caBundle, options.TLSServerName); err != nil {
		return err
	}
	return publish(options.OutputRoot, []materializedFile{
		{name: "ca.crt", mode: 0o444, raw: caBundle},
		{name: "server.crt", mode: 0o444, raw: certificate},
		{name: "server.key", mode: 0o400, raw: privateKey},
	}, options.RuntimeUID, options.RuntimeGID)
}

func validateRuntime(uid, gid int, serverName string) error {
	if !platformSupported() {
		return errors.New("Kubernetes secret materialization is supported only on Linux")
	}
	if os.Geteuid() != 0 && (uid != os.Geteuid() || gid != os.Getegid()) {
		return errors.New("Kubernetes materialization requires root or the exact target runtime identity")
	}
	if uid < 1 || gid < 1 {
		return errors.New("runtime UID and GID must be positive")
	}
	if strings.TrimSpace(serverName) != serverName || serverName == "" || strings.ContainsAny(serverName, "/?#@") {
		return errors.New("TLS server name is required and invalid")
	}
	return nil
}

func readProjectedFile(root, name string, maximum int64) ([]byte, error) {
	if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return nil, fmt.Errorf("projected source root for %s must be a clean absolute path", name)
	}
	rootInfo, err := os.Lstat(root)
	if err != nil || rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() {
		return nil, fmt.Errorf("projected source root for %s must be a real directory", name)
	}
	resolved, err := filepath.EvalSymlinks(filepath.Join(root, name))
	if err != nil {
		return nil, fmt.Errorf("resolve projected %s: %w", name, err)
	}
	relative, err := filepath.Rel(root, resolved)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return nil, fmt.Errorf("projected %s resolves outside its source root", name)
	}
	before, err := os.Lstat(resolved)
	if err != nil || !before.Mode().IsRegular() || before.Size() < 1 || before.Size() > maximum {
		return nil, fmt.Errorf("projected %s must resolve to one bounded regular file", name)
	}
	file, err := os.Open(resolved)
	if err != nil {
		return nil, fmt.Errorf("open projected %s: %w", name, err)
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) {
		return nil, fmt.Errorf("projected %s changed while opening", name)
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || len(raw) < 1 || int64(len(raw)) > maximum {
		return nil, fmt.Errorf("read bounded projected %s", name)
	}
	return raw, nil
}

func validateAdminCredential(raw []byte) error {
	return validateCanonicalLine("admin.token", raw, 32)
}

func validateMasterKey(raw []byte) error {
	value, err := canonicalLine("master.key", raw, 1)
	if err != nil {
		return err
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return errors.New("master.key must be canonical unpadded base64url encoding of 32 bytes")
	}
	clear(decoded)
	return nil
}

func validateCanonicalLine(name string, raw []byte, minimum int) error {
	_, err := canonicalLine(name, raw, minimum)
	return err
}

func canonicalLine(name string, raw []byte, minimum int) (string, error) {
	value := string(raw)
	if strings.HasSuffix(value, "\n") {
		value = strings.TrimSuffix(value, "\n")
	}
	if len(value) < minimum || strings.TrimSpace(value) != value || (string(raw) != value && string(raw) != value+"\n") {
		return "", fmt.Errorf("%s must contain one canonical line", name)
	}
	for index := range len(value) {
		if value[index] < 0x21 || value[index] > 0x7e {
			return "", fmt.Errorf("%s must contain printable ASCII", name)
		}
	}
	return value, nil
}

func validateTLSIdentity(certificatePEM, keyPEM, caPEM []byte, serverName string) error {
	pair, err := tls.X509KeyPair(certificatePEM, keyPEM)
	if err != nil || len(pair.Certificate) == 0 {
		return errors.New("tls.crt and tls.key do not form a valid certificate identity")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil || leaf.VerifyHostname(serverName) != nil {
		return errors.New("TLS leaf certificate does not cover the configured server name")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return errors.New("ca.crt contains no trusted certificates")
	}
	intermediates := x509.NewCertPool()
	for _, raw := range pair.Certificate[1:] {
		parsed, parseErr := x509.ParseCertificate(raw)
		if parseErr != nil {
			return errors.New("tls.crt contains an invalid certificate chain")
		}
		intermediates.AddCert(parsed)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: serverName, Roots: roots, Intermediates: intermediates}); err != nil {
		return errors.New("TLS certificate chain is not valid under ca.crt for the configured server name")
	}
	return nil
}

func publish(outputRoot string, files []materializedFile, uid, gid int) error {
	if outputRoot == "" || !filepath.IsAbs(outputRoot) || filepath.Clean(outputRoot) != outputRoot {
		return errors.New("output root must be a clean absolute path")
	}
	rootInfo, err := os.Lstat(outputRoot)
	if err != nil || rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() {
		return errors.New("output root must be a real directory")
	}
	finalPath := filepath.Join(outputRoot, finalDirectoryName)
	if _, err := os.Lstat(finalPath); err == nil {
		return verifyPublished(finalPath, files, uid, gid)
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.New("inspect published private directory")
	}
	stagePath := filepath.Join(outputRoot, stageDirectoryName)
	if err := os.RemoveAll(stagePath); err != nil {
		return errors.New("clear interrupted private stage")
	}
	if err := os.Mkdir(stagePath, 0o700); err != nil {
		return errors.New("create private stage")
	}
	stagePublished := false
	defer func() {
		if !stagePublished {
			_ = os.RemoveAll(stagePath)
		}
	}()
	for _, item := range files {
		if filepath.Base(item.name) != item.name || item.name == "." {
			return errors.New("materialized file name is invalid")
		}
		if err := writeFile(filepath.Join(stagePath, item.name), item.raw, item.mode, uid, gid); err != nil {
			return fmt.Errorf("materialize %s: %w", item.name, err)
		}
	}
	if err := os.Chmod(stagePath, 0o700); err != nil {
		return errors.New("protect private stage")
	}
	if err := os.Chown(stagePath, uid, gid); err != nil {
		return errors.New("assign private stage ownership")
	}
	if err := syncDirectory(stagePath); err != nil {
		return errors.New("sync private stage")
	}
	if err := os.Rename(stagePath, finalPath); err != nil {
		return errors.New("publish private directory without replacement")
	}
	stagePublished = true
	if err := syncDirectory(outputRoot); err != nil {
		return errors.New("sync private publication")
	}
	return verifyPublished(finalPath, files, uid, gid)
}

func writeFile(path string, raw []byte, mode os.FileMode, uid, gid int) error {
	file, err := openExclusive(path, mode)
	if err != nil {
		return err
	}
	closeWithError := func(current error) error {
		return errors.Join(current, file.Close())
	}
	if _, err := file.Write(raw); err != nil {
		return closeWithError(err)
	}
	if err := file.Sync(); err != nil {
		return closeWithError(err)
	}
	if err := file.Chmod(mode); err != nil {
		return closeWithError(err)
	}
	if err := file.Chown(uid, gid); err != nil {
		return closeWithError(err)
	}
	return file.Close()
}

func verifyPublished(path string, files []materializedFile, uid, gid int) error {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0o700 || !ownedDirectoryBy(info, uid, gid) {
		return errors.New("published private directory has unsafe metadata")
	}
	entries, err := os.ReadDir(path)
	if err != nil || len(entries) != len(files) {
		return errors.New("published private directory has an unexpected inventory")
	}
	expected := make(map[string]materializedFile, len(files))
	for _, item := range files {
		expected[item.name] = item
	}
	for _, entry := range entries {
		item, ok := expected[entry.Name()]
		if !ok {
			return errors.New("published private directory has an unexpected member")
		}
		memberPath := filepath.Join(path, entry.Name())
		memberInfo, err := os.Lstat(memberPath)
		if err != nil || memberInfo.Mode()&os.ModeSymlink != 0 || !memberInfo.Mode().IsRegular() || memberInfo.Mode().Perm() != item.mode || !ownedBy(memberInfo, uid, gid) {
			return fmt.Errorf("published %s has unsafe metadata", item.name)
		}
		raw, err := os.ReadFile(memberPath)
		if err != nil || !bytes.Equal(raw, item.raw) {
			return fmt.Errorf("published %s does not match its projected source", item.name)
		}
	}
	return nil
}

func prepareDataDirectory(path string, uid, gid int) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("data directory must be a clean absolute path")
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("data directory must be a real mounted directory")
	}
	if err := os.Chmod(path, 0o700); err != nil {
		return errors.New("protect data directory")
	}
	if err := os.Chown(path, uid, gid); err != nil {
		return errors.New("assign data directory ownership")
	}
	updated, err := os.Lstat(path)
	if err != nil || updated.Mode().Perm() != 0o700 || !ownedDirectoryBy(updated, uid, gid) {
		return errors.New("data directory ownership did not converge")
	}
	return syncDirectory(filepath.Dir(path))
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

// Inventory returns the stable output filenames for chart/source alignment
// tests without exposing mutable internal slices.
func Inventory(identity, postgres bool) []string {
	result := []string{"admin.token", "ca.crt", "master.key", "server.crt", "server.key"}
	if identity {
		result = append(result, "identity.json", "oidc-client.secret")
	}
	if postgres {
		result = append(result, "postgres.dsn")
	}
	sort.Strings(result)
	return result
}
