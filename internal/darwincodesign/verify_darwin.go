//go:build darwin

package darwincodesign

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"mesh/internal/nodeagent"

	"golang.org/x/sys/unix"
)

const (
	verificationTimeout = 30 * time.Second
	outputLimit         = 32 << 10
)

type Verification struct {
	Role         string
	Identifier   string
	TeamID       string
	PolicySHA256 string
	SHA256       string
	Size         int64
}

// VerifyRelease authenticates all executable code admitted by the macOS node
// release. It accepts no package-provided identity or requirement.
func VerifyRelease(releaseRoot string) ([]Verification, error) {
	if !cleanAbsolutePath(releaseRoot) {
		return nil, errors.New("Darwin signed release root must be a clean absolute non-root path")
	}
	policy, err := LoadPolicy()
	if err != nil {
		return nil, err
	}
	checks := []struct {
		name string
		role string
	}{
		{name: "meshctl", role: MeshctlRole},
		{name: "nebula", role: NebulaRole},
		{name: "nebula-cert", role: NebulaCertRole},
	}
	results := make([]Verification, 0, len(checks))
	for _, check := range checks {
		result, err := verifyFileUsingPolicy(filepath.Join(releaseRoot, "bin", check.name), check.role, policy)
		if err != nil {
			return nil, fmt.Errorf("authenticate Darwin release executable %q: %w", check.name, err)
		}
		results = append(results, result)
	}
	return results, nil
}

// VerifyFile applies the compiled policy to one exact executable role.
func VerifyFile(path, role string) (Verification, error) {
	policy, err := LoadPolicy()
	if err != nil {
		return Verification{}, err
	}
	return verifyFileUsingPolicy(path, role, policy)
}

// VerifyCandidateFile applies the same compiled signature policy to one
// protected release-workspace file owned by the invoking account. It does not
// grant installed-runtime authority; production activation uses VerifyFile,
// whose target must be root:wheel mode-0555.
func VerifyCandidateFile(path, role string) (Verification, error) {
	policy, err := LoadPolicy()
	if err != nil {
		return Verification{}, err
	}
	return verifyFileUsing(path, role, policy, authenticateCandidateTarget)
}

// CreateReceipt verifies the exact four signed candidate paths on a native
// host and returns bounded evidence shared by protected bundle and package
// assembly.
func CreateReceipt(arch string, paths map[string]string, now time.Time) (Receipt, error) {
	if arch != runtime.GOARCH || (arch != "amd64" && arch != "arm64") {
		return Receipt{}, errors.New("Darwin code-signing receipt architecture must exactly match the native host")
	}
	if now.IsZero() {
		return Receipt{}, errors.New("Darwin code-signing receipt time is required")
	}
	policy, err := LoadPolicy()
	if err != nil {
		return Receipt{}, err
	}
	expected := []struct {
		path string
		role string
	}{
		{path: "mesh-install", role: MeshInstallRole},
		{path: "bin/meshctl", role: MeshctlRole},
		{path: "bin/nebula", role: NebulaRole},
		{path: "bin/nebula-cert", role: NebulaCertRole},
	}
	if len(paths) != len(expected) {
		return Receipt{}, errors.New("Darwin code-signing receipt requires exactly four candidate paths")
	}
	files := make([]FileEvidence, 0, len(expected))
	for _, item := range expected {
		absolute, ok := paths[item.path]
		if !ok {
			return Receipt{}, fmt.Errorf("Darwin code-signing receipt path %q is absent", item.path)
		}
		verification, err := verifyFileUsing(absolute, item.role, policy, authenticateCandidateTarget)
		if err != nil {
			return Receipt{}, fmt.Errorf("verify Darwin signed candidate %q: %w", item.path, err)
		}
		files = append(files, FileEvidence{
			Identifier: verification.Identifier, Path: item.path, Role: item.role,
			SHA256: verification.SHA256, Size: verification.Size,
		})
	}
	receipt := Receipt{
		Architecture: arch, Files: files, PolicySHA256: policy.SHA256,
		Schema: ReceiptSchema, TeamID: policy.TeamID,
		VerifiedAt: now.UTC().Truncate(time.Second).Format(time.RFC3339),
	}
	if _, err := EncodeReceipt(receipt); err != nil {
		return Receipt{}, err
	}
	return receipt, nil
}

// VerifyLaunchctl authenticates the fixed Apple launchctl binary against its
// designated requirement. There is intentionally no caller-selected
// platform-tool path or identifier.
func VerifyLaunchctl() error {
	before, err := authenticatePlatformTool(LaunchctlPath)
	if err != nil {
		return err
	}
	if err := runCodesign(codesignSelfVerificationArguments()); err != nil {
		return fmt.Errorf("authenticate fixed Apple codesign tool: %w", err)
	}
	if err := runCodesign(launchctlVerificationArguments()); err != nil {
		return fmt.Errorf("authenticate fixed Apple launchctl tool: %w", err)
	}
	after, err := authenticatePlatformTool(LaunchctlPath)
	if err != nil || after != before {
		return errors.Join(err, errors.New("/bin/launchctl changed during native code-signature verification"))
	}
	return nil
}

func verifyFileUsingPolicy(path, role string, policy Policy) (Verification, error) {
	return verifyFileUsing(path, role, policy, authenticateTarget)
}

type targetAuthenticator func(string) (fileSnapshot, error)

func verifyFileUsing(path, role string, policy Policy, authenticate targetAuthenticator) (Verification, error) {
	if authenticate == nil {
		return Verification{}, errors.New("Darwin code-signing target authenticator is required")
	}
	arguments, err := VerificationArguments(policy, role, path)
	if err != nil {
		return Verification{}, err
	}
	identifier, ok := policy.Identifier(role)
	if !ok {
		return Verification{}, errors.New("Darwin code-signing executable role is unsupported")
	}
	targetBefore, err := authenticate(path)
	if err != nil {
		return Verification{}, err
	}
	if err := runCodesign(codesignSelfVerificationArguments()); err != nil {
		return Verification{}, fmt.Errorf("authenticate fixed Apple codesign tool: %w", err)
	}
	if err := runCodesign(arguments); err != nil {
		return Verification{}, fmt.Errorf("verify strict Developer ID requirement: %w", err)
	}
	targetAfter, err := authenticate(path)
	if err != nil || targetAfter != targetBefore {
		return Verification{}, errors.Join(err, errors.New("Darwin code-signing target changed during native verification"))
	}
	size, digest, err := hashAuthenticatedTarget(path, targetAfter, authenticate)
	if err != nil {
		return Verification{}, err
	}
	return Verification{
		Role: role, Identifier: identifier, TeamID: policy.TeamID, PolicySHA256: policy.SHA256,
		SHA256: digest, Size: size,
	}, nil
}

func runCodesign(arguments []string) error {
	codesignBefore, err := authenticateCodesign()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), verificationTimeout)
	defer cancel()
	var stdout, stderr boundedOutput
	command := exec.CommandContext(ctx, CodesignPath, arguments...)
	command.Env = []string{}
	command.Dir = "/"
	command.Stdin = bytes.NewReader(nil)
	command.Stdout = &stdout
	command.Stderr = &stderr
	command.WaitDelay = 5 * time.Second
	runErr := command.Run()
	codesignAfter, authErr := authenticateCodesign()
	if authErr != nil || codesignAfter != codesignBefore {
		return errors.Join(runErr, authErr, errors.New("/usr/bin/codesign changed while verifying code"))
	}
	if ctx.Err() != nil {
		return fmt.Errorf("codesign verification exceeded its timeout: %w", ctx.Err())
	}
	if stdout.overflow || stderr.overflow {
		return errors.New("codesign verification output exceeded its bound")
	}
	if runErr != nil {
		return fmt.Errorf(
			"codesign verification failed: %w; stdout=%s stderr=%s",
			runErr, outputIdentity(stdout.Bytes()), outputIdentity(stderr.Bytes()),
		)
	}
	if stdout.Len() != 0 || stderr.Len() != 0 {
		return fmt.Errorf(
			"codesign verification succeeded with unexpected output; stdout=%s stderr=%s",
			outputIdentity(stdout.Bytes()), outputIdentity(stderr.Bytes()),
		)
	}
	return nil
}

type fileSnapshot struct {
	device, inode uint64
	mode          uint32
	links         uint16
	uid, gid      uint32
	size          int64
	modifiedS     int64
	modifiedNS    int64
	changedS      int64
	changedNS     int64
	flags         uint32
	generation    uint32
}

func authenticateTarget(path string) (fileSnapshot, error) {
	if err := nodeagent.InspectDarwinPackagedExecutable(path); err != nil {
		return fileSnapshot{}, fmt.Errorf("authenticate Darwin signed executable path: %w", err)
	}
	return snapshotPath(path, true)
}

func hashAuthenticatedTarget(path string, expected fileSnapshot, authenticate targetAuthenticator) (size int64, digest string, returnErr error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW_ANY|unix.O_NONBLOCK, 0)
	if err != nil {
		return 0, "", err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return 0, "", errors.New("adopt Darwin signed executable hash descriptor")
	}
	defer func() { returnErr = errors.Join(returnErr, file.Close()) }()
	var openedBefore, openedAfter, visibleAfter unix.Stat_t
	if err := unix.Fstat(fd, &openedBefore); err != nil || codeSigningSnapshot(openedBefore) != expected {
		return 0, "", errors.Join(err, errors.New("Darwin signed executable changed before hashing"))
	}
	hash := sha256.New()
	read, err := io.Copy(hash, io.LimitReader(file, expected.size+1))
	if err != nil || read != expected.size {
		return 0, "", errors.Join(err, errors.New("Darwin signed executable changed while hashing"))
	}
	if err := unix.Fstat(fd, &openedAfter); err != nil {
		return 0, "", err
	}
	if err := unix.Lstat(path, &visibleAfter); err != nil {
		return 0, "", err
	}
	if codeSigningSnapshot(openedAfter) != expected || codeSigningSnapshot(visibleAfter) != expected {
		return 0, "", errors.New("Darwin signed executable changed after hashing")
	}
	if _, err := authenticate(path); err != nil {
		return 0, "", err
	}
	return read, hex.EncodeToString(hash.Sum(nil)), nil
}

func authenticateCodesign() (fileSnapshot, error) {
	if err := nodeagent.InspectDarwinSensitivePath(CodesignPath); err != nil {
		return fileSnapshot{}, fmt.Errorf("authenticate /usr/bin/codesign path: %w", err)
	}
	return snapshotPath(CodesignPath, false)
}

func authenticateCandidateTarget(path string) (fileSnapshot, error) {
	if err := nodeagent.InspectDarwinSensitivePath(path); err != nil {
		return fileSnapshot{}, fmt.Errorf("authenticate Darwin signed candidate path: %w", err)
	}
	return snapshotPathForOwner(path, true, uint32(os.Geteuid()), false)
}

func authenticatePlatformTool(path string) (fileSnapshot, error) {
	if err := nodeagent.InspectDarwinSensitivePath(path); err != nil {
		return fileSnapshot{}, fmt.Errorf("authenticate Apple platform tool path: %w", err)
	}
	return snapshotPath(path, false)
}

func snapshotPath(path string, exactPackagedMode bool) (result fileSnapshot, returnErr error) {
	return snapshotPathForOwner(path, exactPackagedMode, 0, true)
}

func snapshotPathForOwner(path string, exactPackagedMode bool, ownerUID uint32, requireWheel bool) (result fileSnapshot, returnErr error) {
	var visibleBefore, opened, visibleAfter unix.Stat_t
	if err := unix.Lstat(path, &visibleBefore); err != nil {
		return result, err
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW_ANY|unix.O_NONBLOCK, 0)
	if err != nil {
		return result, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return result, errors.New("adopt Darwin code-signing file descriptor")
	}
	defer func() { returnErr = errors.Join(returnErr, file.Close()) }()
	if err := unix.Fstat(fd, &opened); err != nil {
		return result, err
	}
	if err := unix.Lstat(path, &visibleAfter); err != nil {
		return result, err
	}
	before := codeSigningSnapshot(visibleBefore)
	if before != codeSigningSnapshot(opened) || before != codeSigningSnapshot(visibleAfter) {
		return result, errors.New("Darwin code-signing path changed while anchoring")
	}
	mode := opened.Mode & 0o7777
	if opened.Mode&unix.S_IFMT != unix.S_IFREG || opened.Uid != ownerUID || requireWheel && opened.Gid != 0 ||
		opened.Nlink != 1 || opened.Size < 1 || opened.Size > 256<<20 ||
		mode&0o022 != 0 || mode&0o111 == 0 {
		return result, errors.New("Darwin code-signing path must be one bounded root:wheel nonwritable executable")
	}
	if exactPackagedMode && mode != 0o555 {
		return result, errors.New("Darwin signed release executable must be exact mode-0555")
	}
	return before, nil
}

func codeSigningSnapshot(stat unix.Stat_t) fileSnapshot {
	return fileSnapshot{
		device: uint64(stat.Dev), inode: stat.Ino, mode: uint32(stat.Mode), links: stat.Nlink,
		uid: stat.Uid, gid: stat.Gid, size: stat.Size,
		modifiedS: stat.Mtim.Sec, modifiedNS: stat.Mtim.Nsec,
		changedS: stat.Ctim.Sec, changedNS: stat.Ctim.Nsec,
		flags: stat.Flags, generation: stat.Gen,
	}
}

type boundedOutput struct {
	bytes.Buffer
	overflow bool
}

func (output *boundedOutput) Write(content []byte) (int, error) {
	remaining := outputLimit - output.Len()
	if remaining <= 0 {
		output.overflow = true
		return 0, errors.New("codesign output limit reached")
	}
	if len(content) > remaining {
		written, _ := output.Buffer.Write(content[:remaining])
		output.overflow = true
		return written, errors.New("codesign output limit reached")
	}
	return output.Buffer.Write(content)
}

func outputIdentity(content []byte) string {
	digest := sha256.Sum256(content)
	return fmt.Sprintf("%d-bytes-sha256-%s", len(content), hex.EncodeToString(digest[:]))
}
