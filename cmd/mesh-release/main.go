// mesh-release is an offline release-signing utility. It never downloads,
// extracts, installs, or starts software.
package main

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"mesh/internal/buildinfo"
	"mesh/internal/installtrust"
	releasetrust "mesh/internal/release"
	"mesh/internal/windowsauthenticode"
)

const releaseUsage = "usage: mesh-release <generate-key|export-public|sign|create-root|inspect-root|assemble-root-update|create-bootstrap-manifest|create-bootstrap-handoff|create-bootstrap-anchor|verify-bootstrap|create-release-manifest|create-channel-manifest|build-identity|installer-policy|windows-authenticode-policy|verify-windows-native-evidence|verify-darwin-native-evidence|assemble-online-bundle|assemble-snapshot|assemble-darwin-snapshot|create-origin-index|publish-origin-generation|inspect-origin-generation> [flags]"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "generate-key":
		err = generateKey(os.Args[2:], os.Stdout)
	case "export-public":
		err = exportPublic(os.Args[2:], os.Stdout)
	case "sign":
		err = sign(os.Args[2:], os.Stdout)
	case "create-root":
		err = createRoot(os.Args[2:], os.Stdout)
	case "inspect-root":
		err = inspectRoot(os.Args[2:], os.Stdout)
	case "assemble-root-update":
		err = assembleRootUpdate(os.Args[2:], os.Stdout)
	case "create-bootstrap-manifest":
		err = createBootstrapManifest(os.Args[2:], os.Stdout)
	case "create-bootstrap-handoff":
		err = createBootstrapHandoff(os.Args[2:], os.Stdout)
	case "create-bootstrap-anchor":
		err = createBootstrapAnchor(os.Args[2:], os.Stdout)
	case "verify-bootstrap":
		err = verifyBootstrap(os.Args[2:], os.Stdout)
	case "create-release-manifest":
		err = createReleaseManifest(os.Args[2:], os.Stdout)
	case "create-channel-manifest":
		err = createChannelManifest(os.Args[2:], os.Stdout)
	case "build-identity":
		err = buildIdentity(os.Args[2:], os.Stdout)
	case "installer-policy":
		err = installerPolicy(os.Args[2:], os.Stdout)
	case "windows-authenticode-policy":
		err = windowsAuthenticodePolicy(os.Args[2:], os.Stdout)
	case "verify-windows-native-evidence":
		err = verifyWindowsNativeEvidence(os.Args[2:], os.Stdout)
	case "verify-darwin-native-evidence":
		err = verifyDarwinNativeEvidence(os.Args[2:], os.Stdout)
	case "assemble-online-bundle":
		err = assembleOnlineBundle(os.Args[2:], os.Stdout)
	case "assemble-snapshot":
		err = assembleSnapshot(os.Args[2:], os.Stdout)
	case "assemble-darwin-snapshot":
		err = assembleDarwinSnapshot(os.Args[2:], os.Stdout)
	case "create-origin-index":
		err = createOriginIndex(os.Args[2:], os.Stdout)
	case "publish-origin-generation":
		err = publishOriginGeneration(os.Args[2:], os.Stdout)
	case "inspect-origin-generation":
		err = inspectOriginGeneration(os.Args[2:], os.Stdout)
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "mesh-release:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, releaseUsage)
}

func buildIdentity(args []string, output io.Writer) error {
	flags := flag.NewFlagSet("build-identity", flag.ContinueOnError)
	version := flags.String("version", "", "canonical release SemVer")
	commit := flags.String("commit", "", "exact 40-character lowercase hexadecimal source commit")
	buildTime := flags.String("build-time", "", "canonical UTC RFC3339 build time")
	securityFloor := flags.Uint64("security-floor", 0, "positive supported installer security floor")
	agentStateReadMin := flags.Uint64("agent-state-read-min", 0, "oldest positive agent-state schema this build can read")
	agentStateReadMax := flags.Uint64("agent-state-read-max", 0, "newest positive agent-state schema this build can read")
	agentStateWriteVersion := flags.Uint64("agent-state-write-version", 0, "positive agent-state schema this build writes")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("build-identity does not accept positional arguments")
	}
	frame, err := buildinfo.EncodeIdentity(buildinfo.IdentityInfo{
		Schema: buildinfo.Schema, Version: *version, Commit: *commit,
		BuildTime: *buildTime, SecurityFloor: *securityFloor,
		AgentStateReadMin: *agentStateReadMin, AgentStateReadMax: *agentStateReadMax,
		AgentStateWriteVersion: *agentStateWriteVersion,
	})
	if err != nil {
		return fmt.Errorf("encode build identity: %w", err)
	}
	_, err = fmt.Fprintln(output, frame)
	return err
}

type repeatedFlag []string

func (values *repeatedFlag) String() string { return strings.Join(*values, ",") }
func (values *repeatedFlag) Set(value string) error {
	if strings.TrimSpace(value) == "" {
		return errors.New("flag value cannot be empty")
	}
	*values = append(*values, value)
	return nil
}

func installerPolicy(args []string, output io.Writer) error {
	flags := flag.NewFlagSet("installer-policy", flag.ContinueOnError)
	rootPath := flags.String("root", "", "canonical version-1, epoch-1 initial release root")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("installer-policy does not accept positional arguments")
	}
	if strings.TrimSpace(*rootPath) == "" {
		return errors.New("--root is required")
	}
	raw, err := readAuthoringPublicFile("initial release root", *rootPath, releasetrust.MaxRootSize)
	if err != nil {
		return fmt.Errorf("read initial release root: %w", err)
	}
	encoded, _, err := installtrust.EncodeBootstrap(installtrust.BootstrapSpec{InitialRoot: raw})
	if err != nil {
		return fmt.Errorf("encode installer bootstrap: %w", err)
	}
	_, err = fmt.Fprintln(output, encoded)
	return err
}

func windowsAuthenticodePolicy(args []string, output io.Writer) error {
	flags := flag.NewFlagSet("windows-authenticode-policy", flag.ContinueOnError)
	var meshPins repeatedFlag
	var wintunPins repeatedFlag
	printSHA256 := flags.Bool("print-sha256", false, "print the canonical policy JSON SHA-256 instead of the linker frame")
	flags.Var(&meshPins, "mesh-signer-spki-sha256", "authorized Mesh code-signing certificate SPKI SHA-256 (repeat for bounded rotation)")
	flags.Var(&wintunPins, "wintun-signer-spki-sha256", "authorized Wintun code-signing certificate SPKI SHA-256 (repeat for bounded rotation)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("windows-authenticode-policy does not accept positional arguments")
	}
	frame, policy, err := windowsauthenticode.EncodePolicy(windowsauthenticode.PolicySpec{
		MeshSignerSPKISHA256:   append([]string(nil), meshPins...),
		WintunSignerSPKISHA256: append([]string(nil), wintunPins...),
	})
	if err != nil {
		return fmt.Errorf("encode Windows Authenticode policy: %w", err)
	}
	value := frame
	if *printSHA256 {
		value = policy.SHA256
	}
	_, err = fmt.Fprintln(output, value)
	return err
}

func generateKey(args []string, output io.Writer) error {
	if err := requirePrivateKeyOperationsSupported(); err != nil {
		return err
	}
	flags := flag.NewFlagSet("generate-key", flag.ContinueOnError)
	privatePath := flags.String("private", "", "new private key file (created 0600, never overwritten)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("generate-key does not accept positional arguments")
	}
	if strings.TrimSpace(*privatePath) == "" {
		return fmt.Errorf("--private is required")
	}
	keyFile, privateKey, err := releasetrust.GeneratePrivateKeyFile()
	if err != nil {
		return err
	}
	defer clear(privateKey)
	raw, err := releasetrust.MarshalPrivateKeyFile(keyFile)
	if err != nil {
		return err
	}
	defer clear(raw)
	if err := writeNewFile(*privatePath, raw, 0o600); err != nil {
		return err
	}
	fmt.Fprintf(output, "Generated private signing key %s in %s (0600).\n", keyFile.KeyID, *privatePath)
	return nil
}

func exportPublic(args []string, output io.Writer) error {
	if err := requirePrivateKeyOperationsSupported(); err != nil {
		return err
	}
	flags := flag.NewFlagSet("export-public", flag.ContinueOnError)
	privatePath := flags.String("private", "", "private key file")
	publicPath := flags.String("public", "", "new public key file (never overwritten)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("export-public does not accept positional arguments")
	}
	if strings.TrimSpace(*privatePath) == "" || strings.TrimSpace(*publicPath) == "" {
		return fmt.Errorf("--private and --public are required")
	}
	privateKey, keyID, err := loadPrivateKey(*privatePath)
	if err != nil {
		return err
	}
	defer clear(privateKey)
	publicFile, err := releasetrust.PublicKeyFileFromPrivate(privateKey)
	if err != nil {
		return err
	}
	if publicFile.KeyID != keyID {
		return fmt.Errorf("private key identity changed during export")
	}
	raw, err := releasetrust.MarshalPublicKeyFile(publicFile)
	if err != nil {
		return err
	}
	if err := writeAuthoringPublicFile("public key", *publicPath, raw, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(output, "Exported public key %s to %s.\n", keyID, *publicPath)
	return nil
}

func sign(args []string, output io.Writer) error {
	if err := requirePrivateKeyOperationsSupported(); err != nil {
		return err
	}
	flags := flag.NewFlagSet("sign", flag.ContinueOnError)
	privatePath := flags.String("private", "", "private key file")
	manifestPath := flags.String("manifest", "", "exact local manifest bytes to sign")
	signaturePath := flags.String("signature", "", "new detached signature envelope (never overwritten)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("sign does not accept positional arguments")
	}
	if strings.TrimSpace(*privatePath) == "" || strings.TrimSpace(*manifestPath) == "" || strings.TrimSpace(*signaturePath) == "" {
		return fmt.Errorf("--private, --manifest, and --signature are required")
	}
	rawManifest, err := readAuthoringPublicFile("manifest", *manifestPath, releasetrust.MaxManifestSize)
	if err != nil {
		return fmt.Errorf("read manifest: %w", err)
	}
	kind := releasetrust.ManifestKind("")
	parsed, releaseErr := releasetrust.ParseManifest(rawManifest, releasetrust.VerificationPolicy{Now: time.Now()})
	if releaseErr == nil {
		kind = parsed.Kind
	} else if _, rootErr := releasetrust.ParseRoot(rawManifest); rootErr == nil {
		kind = releasetrust.RootManifestKind
	} else if _, bootstrapErr := releasetrust.ParseBootstrapManifest(rawManifest, time.Now(), 0); bootstrapErr == nil {
		kind = releasetrust.BootstrapManifestKind
	} else {
		_, rootErr := releasetrust.ParseRoot(rawManifest)
		_, bootstrapErr := releasetrust.ParseBootstrapManifest(rawManifest, time.Now(), 0)
		return fmt.Errorf("validate manifest: release=%v; root=%v; bootstrap=%v", releaseErr, rootErr, bootstrapErr)
	}
	privateKey, keyID, err := loadPrivateKey(*privatePath)
	if err != nil {
		return err
	}
	defer clear(privateKey)
	envelope, err := releasetrust.SignManifest(kind, rawManifest, privateKey)
	if err != nil {
		return err
	}
	if err := writeAuthoringPublicFile("detached signature", *signaturePath, envelope, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(output, "Signed exact %s manifest bytes with %s; wrote %s.\n", kind, keyID, *signaturePath)
	return nil
}

func loadPrivateKey(path string) (ed25519.PrivateKey, string, error) {
	if err := requirePrivateKeyOperationsSupported(); err != nil {
		return nil, "", err
	}
	raw, err := readPrivateFile(path, releasetrust.MaxKeyFileSize)
	if err != nil {
		return nil, "", err
	}
	defer clear(raw)
	keyFile, privateKey, err := releasetrust.ParsePrivateKeyFile(raw)
	if err != nil {
		return nil, "", err
	}
	return privateKey, keyFile.KeyID, nil
}

func readRegularFile(path string, limit int) ([]byte, error) {
	return readCheckedFile(path, limit, false)
}

func readPrivateFile(path string, limit int) ([]byte, error) {
	if err := requirePrivateKeyOperationsSupported(); err != nil {
		return nil, err
	}
	return readCheckedFile(path, limit, true)
}

func readCheckedFile(path string, limit int, requirePrivate bool) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return nil, fmt.Errorf("must be a regular file, not a symlink")
	}
	if requirePrivate {
		if err := validatePrivateFileSecurity(before); err != nil {
			return nil, err
		}
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	after, statErr := file.Stat()
	if statErr != nil || !os.SameFile(before, after) {
		_ = file.Close()
		return nil, fmt.Errorf("file changed while opening")
	}
	if requirePrivate {
		if err := validatePrivateFileSecurity(after); err != nil {
			_ = file.Close()
			return nil, err
		}
	}
	raw, readErr := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	closeErr := file.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if len(raw) == 0 || len(raw) > limit {
		return nil, fmt.Errorf("file size must be between 1 and %d bytes", limit)
	}
	return raw, nil
}

func writeNewFile(path string, content []byte, mode os.FileMode) (returnErr error) {
	return writeNewFileUsing(path, content, mode, func(file *os.File, content []byte) error {
		_, err := io.Copy(file, bytes.NewReader(content))
		return err
	})
}

func writeNewFileUsing(path string, content []byte, mode os.FileMode, writeContent func(*os.File, []byte) error) (returnErr error) {
	return writeNewFileUsingAndSync(path, content, mode, writeContent, syncOutputParent)
}

func writeNewFileUsingAndSync(path string, content []byte, mode os.FileMode, writeContent func(*os.File, []byte) error, syncParent func(string) error) (returnErr error) {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("refusing to overwrite existing file %s", path)
		}
		return err
	}
	removePartial := true
	defer func() {
		if removePartial {
			_ = file.Close()
			if removeErr := os.Remove(path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
				if returnErr != nil {
					returnErr = fmt.Errorf("%w; remove partial output: %v", returnErr, removeErr)
				} else {
					returnErr = fmt.Errorf("remove partial output: %w", removeErr)
				}
			}
			// Best effort: make removal of a partial or uncommitted output
			// durable without obscuring the primary failure.
			_ = syncParent(path)
		}
	}()
	if err := file.Chmod(mode); err != nil {
		return err
	}
	if err := writeContent(file, content); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := syncParent(path); err != nil {
		return fmt.Errorf("sync output parent directory: %w", err)
	}
	removePartial = false
	return nil
}
