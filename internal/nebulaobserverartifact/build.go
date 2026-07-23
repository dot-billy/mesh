package nebulaobserverartifact

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	observerassets "mesh/third_party/nebula-observer"
)

type BuildResult struct {
	OutputDir  string
	Target     Target
	Identity   Identity
	Manifest   Manifest
	FileCount  int
	TotalBytes int64
}

// Build constructs the exact observer-enabled Nebula runtime twice from the
// locked module-cache source, requires byte-for-byte reproducibility, and
// publishes a new authenticated staging directory without replacement.
func Build(ctx context.Context, arch, outputDir string) (BuildResult, error) {
	policy, policyDigest, err := EmbeddedPolicy()
	if err != nil {
		return BuildResult{}, err
	}
	target, err := policy.Select(strings.TrimSpace(arch))
	if err != nil {
		return BuildResult{}, err
	}
	return buildSelected(ctx, outputDir, policy, policyDigest, ManifestSchema, target)
}

// BuildWindows constructs the exact security-patched Windows Nebula runtime
// twice from the same source/patch lock. The Linux observer transport compiles
// to its reviewed no-op non-Linux stub; this function makes no Windows service,
// DACL, or Authenticode claim.
func BuildWindows(ctx context.Context, arch, outputDir string) (BuildResult, error) {
	policy, _, err := EmbeddedPolicy()
	if err != nil {
		return BuildResult{}, err
	}
	target, policyDigest, err := selectWindowsTarget(strings.TrimSpace(arch))
	if err != nil {
		return BuildResult{}, err
	}
	return buildSelected(ctx, outputDir, policy, policyDigest, WindowsManifestSchema, target)
}

// BuildDarwin constructs the exact security-patched Darwin Nebula runtime
// twice from the common source/patch lock. The observer transport compiles to
// its reviewed no-I/O stub; this function makes no launchd, extended-ACL,
// codesigning, notarization, or native-installation claim.
func BuildDarwin(ctx context.Context, arch, outputDir string) (BuildResult, error) {
	policy, _, err := EmbeddedPolicy()
	if err != nil {
		return BuildResult{}, err
	}
	target, policyDigest, err := selectDarwinTarget(strings.TrimSpace(arch))
	if err != nil {
		return BuildResult{}, err
	}
	return buildSelected(ctx, outputDir, policy, policyDigest, DarwinManifestSchema, target)
}

func buildSelected(ctx context.Context, outputDir string, policy Policy, policyDigest, manifestSchema string, target TargetLock) (BuildResult, error) {
	if ctx == nil {
		return BuildResult{}, errors.New("build context is nil")
	}
	if err := ctx.Err(); err != nil {
		return BuildResult{}, err
	}
	if runtime.GOOS != "linux" {
		return BuildResult{}, errors.New("observer artifacts can only be built on Linux")
	}
	outputDir, err := preflightNewOutput(outputDir)
	if err != nil {
		return BuildResult{}, err
	}
	goBinary, err := resolveGoToolchain(ctx, policy.Toolchain)
	if err != nil {
		return BuildResult{}, err
	}
	moduleCache, sourcePath, err := lockedModuleSource(ctx)
	if err != nil {
		return BuildResult{}, err
	}
	sourceDigest, _, _, err := hashSourceTree(sourcePath)
	if err != nil {
		return BuildResult{}, fmt.Errorf("authenticate cached Nebula source: %w", err)
	}
	if sourceDigest != policy.SourceTreeSHA256 {
		return BuildResult{}, fmt.Errorf("cached Nebula source-tree SHA-256 is %s, lock records %s", sourceDigest, policy.SourceTreeSHA256)
	}
	scratch, err := os.MkdirTemp("", "mesh-nebula-observer-build-")
	if err != nil {
		return BuildResult{}, fmt.Errorf("create private observer build directory: %w", err)
	}
	defer func() {
		_ = os.Chmod(scratch, 0o700)
		_ = os.RemoveAll(scratch)
	}()
	if err := os.Chmod(scratch, 0o700); err != nil {
		return BuildResult{}, fmt.Errorf("make observer build directory private: %w", err)
	}
	sourceCopy := filepath.Join(scratch, "source")
	if err := copySourceTree(sourcePath, sourceCopy); err != nil {
		return BuildResult{}, err
	}
	copyDigest, _, _, err := hashSourceTree(sourceCopy)
	if err != nil {
		return BuildResult{}, fmt.Errorf("verify copied Nebula source: %w", err)
	}
	currentSourceDigest, _, _, sourceErr := hashSourceTree(sourcePath)
	if sourceErr != nil || copyDigest != policy.SourceTreeSHA256 || currentSourceDigest != policy.SourceTreeSHA256 {
		return BuildResult{}, fmt.Errorf("Nebula source changed during private copy: copy=%s source=%s error=%v", copyDigest, currentSourceDigest, sourceErr)
	}
	if err := applyLockedPatches(ctx, sourceCopy, policy); err != nil {
		return BuildResult{}, err
	}
	patchedDigest, _, _, err := hashSourceTree(sourceCopy)
	if err != nil {
		return BuildResult{}, fmt.Errorf("fingerprint patched Nebula source: %w", err)
	}
	if patchedDigest != policy.PatchedTreeSHA256 {
		return BuildResult{}, fmt.Errorf("patched Nebula source-tree SHA-256 is %s, lock records %s", patchedDigest, policy.PatchedTreeSHA256)
	}
	first, err := buildPass(ctx, goBinary, sourceCopy, moduleCache, scratch, "first", policy, target)
	if err != nil {
		return BuildResult{}, err
	}
	second, err := buildPass(ctx, goBinary, sourceCopy, moduleCache, scratch, "second", policy, target)
	if err != nil {
		return BuildResult{}, err
	}
	var mismatches []string
	for _, entry := range target.Entries {
		left, right := first[entry.Name], second[entry.Name]
		if !bytes.Equal(left, right) {
			return BuildResult{}, fmt.Errorf("observer entry %q is not reproducible across clean build caches", entry.Name)
		}
		digest := sha256.Sum256(left)
		actualDigest := hex.EncodeToString(digest[:])
		if int64(len(left)) != entry.Size || actualDigest != entry.SHA256 {
			mismatches = append(mismatches, fmt.Sprintf("%s size=%d sha256=%s (lock size=%d sha256=%s)", entry.Name, len(left), actualDigest, entry.Size, entry.SHA256))
		}
	}
	if len(mismatches) != 0 {
		return BuildResult{}, fmt.Errorf("observer build output differs from lock: %s", strings.Join(mismatches, "; "))
	}
	afterBuildDigest, _, _, err := hashSourceTree(sourceCopy)
	if err != nil || afterBuildDigest != policy.PatchedTreeSHA256 {
		return BuildResult{}, fmt.Errorf("patched source changed during builds: digest=%s error=%v", afterBuildDigest, err)
	}
	verified, err := publishStage(outputDir, policy, policyDigest, manifestSchema, target, first)
	if err != nil {
		return BuildResult{}, err
	}
	return BuildResult(verified), nil
}

func preflightNewOutput(outputDir string) (string, error) {
	absolute, err := filepath.Abs(strings.TrimSpace(outputDir))
	if err != nil || strings.TrimSpace(outputDir) == "" {
		return "", errors.New("observer output directory is required")
	}
	absolute = filepath.Clean(absolute)
	parentPath, outputName := filepath.Split(absolute)
	parentPath = filepath.Clean(parentPath)
	if outputName == "" || outputName == "." || outputName == ".." {
		return "", errors.New("observer output must name a new child directory")
	}
	parentPath, _, err = inspectRealDirectory(parentPath, "observer output parent")
	if err != nil {
		return "", err
	}
	resolvedParent, err := filepath.EvalSymlinks(parentPath)
	if err != nil || filepath.Clean(resolvedParent) != parentPath {
		return "", errors.New("observer output parent path cannot traverse symlinks")
	}
	if _, err := os.Lstat(absolute); err == nil {
		return "", fmt.Errorf("observer output %q already exists", absolute)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("inspect observer output: %w", err)
	}
	return absolute, nil
}

func resolveGoToolchain(ctx context.Context, want string) (string, error) {
	command := exec.CommandContext(ctx, "go", "env", "GOROOT")
	command.Env = toolchainSelectionEnvironment(want)
	output, err := command.Output()
	if err != nil {
		return "", fmt.Errorf("resolve locked Go toolchain %q from the authenticated local cache: %w", want, err)
	}
	toolRoot, _, err := inspectRealDirectory(strings.TrimSpace(string(output)), "locked Go toolchain root")
	if err != nil {
		return "", err
	}
	resolvedRoot, err := filepath.EvalSymlinks(toolRoot)
	if err != nil || filepath.Clean(resolvedRoot) != toolRoot {
		return "", errors.New("locked Go toolchain root cannot traverse symlinks")
	}
	goBinary := filepath.Join(toolRoot, "bin", "go")
	info, err := os.Lstat(goBinary)
	if err != nil {
		return "", fmt.Errorf("inspect locked Go toolchain executable: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || hasSpecialMode(info.Mode()) || info.Mode().Perm()&0o111 == 0 {
		return "", errors.New("locked Go toolchain executable is not an ordinary executable file")
	}
	resolvedBinary, err := filepath.EvalSymlinks(goBinary)
	if err != nil || filepath.Clean(resolvedBinary) != goBinary {
		return "", errors.New("locked Go toolchain executable cannot traverse symlinks")
	}
	command = exec.CommandContext(ctx, goBinary, "version")
	command.Env = buildEnvironment("", "", "", "", "")
	output, err = command.Output()
	if err != nil {
		return "", fmt.Errorf("inspect locked Go toolchain executable: %w", err)
	}
	fields := strings.Fields(string(output))
	if len(fields) < 3 || fields[0] != "go" || fields[1] != "version" || fields[2] != want {
		return "", fmt.Errorf("Go toolchain identity is %q, want %q", strings.TrimSpace(string(output)), want)
	}
	return goBinary, nil
}

func lockedModuleSource(ctx context.Context) (string, string, error) {
	command := exec.CommandContext(ctx, "go", "env", "GOMODCACHE")
	command.Env = buildEnvironment("", "", "", "", "")
	output, err := command.Output()
	if err != nil {
		return "", "", fmt.Errorf("locate Go module cache: %w", err)
	}
	moduleCache, _, err := inspectRealDirectory(strings.TrimSpace(string(output)), "Go module cache")
	if err != nil {
		return "", "", err
	}
	resolvedCache, err := filepath.EvalSymlinks(moduleCache)
	if err != nil || filepath.Clean(resolvedCache) != moduleCache {
		return "", "", errors.New("Go module cache path cannot traverse symlinks")
	}
	sourcePath := filepath.Join(moduleCache, "github.com", "slackhq", "nebula@v1.10.3")
	sourcePath, _, err = inspectRealDirectory(sourcePath, "cached Nebula module")
	if err != nil {
		return "", "", err
	}
	resolvedSource, err := filepath.EvalSymlinks(sourcePath)
	if err != nil || filepath.Clean(resolvedSource) != sourcePath {
		return "", "", errors.New("cached Nebula module path cannot traverse symlinks")
	}
	return moduleCache, sourcePath, nil
}

func applyLockedPatches(ctx context.Context, sourcePath string, policy Policy) error {
	for _, patch := range policy.Patches {
		raw, err := observerassets.Patch(patch.Name)
		if err != nil {
			return fmt.Errorf("read embedded patch %q: %w", patch.Name, err)
		}
		for _, check := range []bool{true, false} {
			arguments := []string{"apply", "--whitespace=error-all"}
			if check {
				arguments = append(arguments, "--check")
			}
			arguments = append(arguments, "-")
			command := exec.CommandContext(ctx, "git", arguments...)
			command.Dir = sourcePath
			command.Env = buildEnvironment("", "", "", "", "")
			command.Stdin = bytes.NewReader(raw)
			output, commandErr := command.CombinedOutput()
			if commandErr != nil {
				action := "apply"
				if check {
					action = "check"
				}
				return fmt.Errorf("%s observer patch %q: %w: %s", action, patch.Name, commandErr, strings.TrimSpace(string(output)))
			}
		}
	}
	return nil
}

func buildPass(ctx context.Context, goBinary, sourcePath, moduleCache, scratch, pass string, policy Policy, target TargetLock) (map[string][]byte, error) {
	passRoot := filepath.Join(scratch, pass)
	cachePath := filepath.Join(passRoot, "cache")
	temporaryPath := filepath.Join(passRoot, "tmp")
	outputPath := filepath.Join(passRoot, "output")
	for _, directory := range []string{passRoot, cachePath, temporaryPath, outputPath} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			return nil, fmt.Errorf("create private %s build directory: %w", pass, err)
		}
	}
	result := make(map[string][]byte, len(target.Entries))
	for _, entry := range target.Entries {
		packagePath := "./cmd/" + strings.TrimSuffix(entry.Name, ".exe")
		destination := filepath.Join(outputPath, entry.Name)
		arguments := []string{"build"}
		arguments = append(arguments, policy.BuildFlags...)
		arguments = append(arguments, "-o", destination, packagePath)
		command := exec.CommandContext(ctx, goBinary, arguments...)
		command.Dir = sourcePath
		command.Env = buildTargetEnvironment(target.OS, target.Arch, moduleCache, cachePath, temporaryPath, scratch)
		output, commandErr := command.CombinedOutput()
		if commandErr != nil {
			return nil, fmt.Errorf("%s build of %s: %w: %s", pass, entry.Name, commandErr, strings.TrimSpace(string(output)))
		}
		if err := os.Chmod(destination, 0o555); err != nil {
			return nil, fmt.Errorf("lock %s build output mode: %w", entry.Name, err)
		}
		content, err := readStableRegular(destination, 0o555, maximumBinarySize)
		if err != nil {
			return nil, fmt.Errorf("snapshot %s build output: %w", entry.Name, err)
		}
		if err := verifyBinary(content, entry, Target{OS: target.OS, Arch: target.Arch}, policy); err != nil {
			return nil, fmt.Errorf("verify %s build output: %w", entry.Name, err)
		}
		result[entry.Name] = content
	}
	return result, nil
}

func toolchainSelectionEnvironment(want string) []string {
	replaced := map[string]string{
		"GOENV":       "off",
		"GOFLAGS":     "",
		"GONOPROXY":   "",
		"GONOSUMDB":   "",
		"GOPROXY":     "off",
		"GOSUMDB":     "sum.golang.org",
		"GOTELEMETRY": "off",
		"GOTOOLCHAIN": want,
		"GOWORK":      "off",
	}
	environment := make([]string, 0, len(os.Environ())+len(replaced))
	for _, pair := range os.Environ() {
		key, _, _ := strings.Cut(pair, "=")
		if _, replacedKey := replaced[key]; !replacedKey {
			environment = append(environment, pair)
		}
	}
	for key, value := range replaced {
		environment = append(environment, key+"="+value)
	}
	return environment
}

func buildEnvironment(arch, moduleCache, cachePath, temporaryPath, scratch string) []string {
	return buildTargetEnvironment("linux", arch, moduleCache, cachePath, temporaryPath, scratch)
}

func buildTargetEnvironment(goos, arch, moduleCache, cachePath, temporaryPath, scratch string) []string {
	replaced := map[string]string{
		"CGO_ENABLED": "0", "GOOS": goos, "GOARCH": arch,
		"GOAMD64": "v1", "GOARM64": "v8.0", "GOENV": "off", "GOEXPERIMENT": "",
		"GOFIPS140": "off", "GOFLAGS": "-mod=readonly", "GOPROXY": "off", "GOSUMDB": "off",
		"GOTOOLCHAIN": "local", "GOWORK": "off", "GOCACHE": cachePath, "GOTMPDIR": temporaryPath,
		"GOMODCACHE": moduleCache, "LC_ALL": "C", "TZ": "UTC", "TMPDIR": scratch,
	}
	if arch == "" {
		delete(replaced, "GOARCH")
		delete(replaced, "CGO_ENABLED")
	}
	for key, value := range replaced {
		if value == "" && key != "GOEXPERIMENT" {
			delete(replaced, key)
		}
	}
	environment := make([]string, 0, len(os.Environ())+len(replaced))
	for _, pair := range os.Environ() {
		key, _, _ := strings.Cut(pair, "=")
		if _, replacedKey := replaced[key]; !replacedKey {
			environment = append(environment, pair)
		}
	}
	for key, value := range replaced {
		environment = append(environment, key+"="+value)
	}
	return environment
}

func publishStage(outputDir string, policy Policy, policyDigest, manifestSchema string, target TargetLock, binaries map[string][]byte) (VerificationResult, error) {
	absolute, err := filepath.Abs(strings.TrimSpace(outputDir))
	if err != nil || strings.TrimSpace(outputDir) == "" {
		return VerificationResult{}, errors.New("observer output directory is required")
	}
	absolute = filepath.Clean(absolute)
	parentPath, outputName := filepath.Split(absolute)
	parentPath = filepath.Clean(parentPath)
	if outputName == "" || outputName == "." || outputName == ".." {
		return VerificationResult{}, errors.New("observer output must name a new child directory")
	}
	parentPath, parentInfo, err := inspectRealDirectory(parentPath, "observer output parent")
	if err != nil {
		return VerificationResult{}, err
	}
	resolvedParent, err := filepath.EvalSymlinks(parentPath)
	if err != nil || filepath.Clean(resolvedParent) != parentPath {
		return VerificationResult{}, errors.New("observer output parent path cannot traverse symlinks")
	}
	parent, err := os.Open(parentPath)
	if err != nil {
		return VerificationResult{}, fmt.Errorf("open observer output parent: %w", err)
	}
	defer parent.Close()
	openedParent, err := parent.Stat()
	if err != nil || !stableFileInfo(parentInfo, openedParent) {
		return VerificationResult{}, errors.New("observer output parent changed while opening")
	}
	root, err := os.OpenRoot(parentPath)
	if err != nil {
		return VerificationResult{}, fmt.Errorf("anchor observer output parent: %w", err)
	}
	defer root.Close()
	if _, err := root.Lstat(outputName); err == nil {
		return VerificationResult{}, fmt.Errorf("observer output %q already exists", absolute)
	} else if !errors.Is(err, os.ErrNotExist) {
		return VerificationResult{}, fmt.Errorf("inspect observer output: %w", err)
	}
	stageName, err := randomPrivateName(".mesh-nebula-observer-stage-")
	if err != nil {
		return VerificationResult{}, err
	}
	if err := root.Mkdir(stageName, 0o700); err != nil {
		return VerificationResult{}, fmt.Errorf("create private observer stage: %w", err)
	}
	stageOwned := true
	defer func() {
		if stageOwned {
			_ = root.Chmod(stageName, 0o700)
			_ = root.RemoveAll(stageName)
		}
	}()
	stage, err := root.OpenRoot(stageName)
	if err != nil {
		return VerificationResult{}, fmt.Errorf("open private observer stage: %w", err)
	}
	stageClosed := false
	defer func() {
		if !stageClosed {
			_ = stage.Close()
		}
	}()
	manifest := Manifest{
		Schema: manifestSchema, PolicySHA256: policyDigest,
		Target: Target{OS: target.OS, Arch: target.Arch}, GoVersion: policy.Toolchain,
		Entries: append([]EntryLock(nil), target.Entries...),
	}
	manifestBytes, err := marshalManifest(manifest)
	if err != nil {
		return VerificationResult{}, err
	}
	files := map[string]struct {
		mode    uint32
		content []byte
	}{manifestName: {mode: manifestMode, content: manifestBytes}}
	for _, entry := range target.Entries {
		files[entry.Name] = struct {
			mode    uint32
			content []byte
		}{mode: entry.Mode, content: binaries[entry.Name]}
	}
	orderedNames := []string{manifestName}
	for _, entry := range target.Entries {
		orderedNames = append(orderedNames, entry.Name)
	}
	for _, name := range orderedNames {
		file := files[name]
		if len(file.content) == 0 {
			return VerificationResult{}, fmt.Errorf("observer stage content %q is empty", name)
		}
		output, err := stage.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, os.FileMode(file.mode))
		if err != nil {
			return VerificationResult{}, fmt.Errorf("create observer stage file %q: %w", name, err)
		}
		written, writeErr := output.Write(file.content)
		chmodErr := output.Chmod(os.FileMode(file.mode))
		syncErr := output.Sync()
		closeErr := output.Close()
		if writeErr != nil || written != len(file.content) || chmodErr != nil || syncErr != nil || closeErr != nil {
			return VerificationResult{}, fmt.Errorf("finish observer stage file %q: write=%v chmod=%v sync=%v close=%v", name, writeErr, chmodErr, syncErr, closeErr)
		}
	}
	if err := stage.Chmod(".", 0o555); err != nil {
		return VerificationResult{}, fmt.Errorf("lock observer stage directory mode: %w", err)
	}
	stageInfo, err := stage.Stat(".")
	if err != nil {
		return VerificationResult{}, fmt.Errorf("inspect completed observer stage: %w", err)
	}
	if err := syncRootDirectory(stage); err != nil {
		return VerificationResult{}, fmt.Errorf("sync completed observer stage: %w", err)
	}
	if err := stage.Close(); err != nil {
		stageClosed = true
		return VerificationResult{}, fmt.Errorf("close completed observer stage: %w", err)
	}
	stageClosed = true
	if _, err := root.Lstat(outputName); err == nil {
		return VerificationResult{}, fmt.Errorf("observer output %q appeared during build", absolute)
	} else if !errors.Is(err, os.ErrNotExist) {
		return VerificationResult{}, fmt.Errorf("recheck observer output: %w", err)
	}
	if err := renameNoReplace(parent, stageName, outputName); err != nil {
		return VerificationResult{}, fmt.Errorf("publish observer stage without replacement: %w", err)
	}
	stageOwned = false
	cleanupPublished := func() (error, error) {
		_ = root.Chmod(outputName, 0o700)
		removeErr := root.RemoveAll(outputName)
		return removeErr, syncOpenDirectory(parent)
	}
	if err := syncOpenDirectory(parent); err != nil {
		removeErr, cleanupSyncErr := cleanupPublished()
		return VerificationResult{}, fmt.Errorf("sync observer stage publication: %w; cleanup remove=%v sync=%v", err, removeErr, cleanupSyncErr)
	}
	published, err := root.Lstat(outputName)
	pathPublished, pathErr := os.Lstat(absolute)
	latestParent, parentErr := os.Lstat(parentPath)
	if err != nil || pathErr != nil || parentErr != nil || !stableFileInfo(stageInfo, published) ||
		!stableFileInfo(stageInfo, pathPublished) || !os.SameFile(openedParent, latestParent) || openedParent.Mode() != latestParent.Mode() {
		removeErr, cleanupSyncErr := cleanupPublished()
		return VerificationResult{}, fmt.Errorf("published observer stage identity or ancestry changed; cleanup remove=%v sync=%v", removeErr, cleanupSyncErr)
	}
	verified, err := verifyStagedDirectoryTarget(absolute, target.OS, target.Arch)
	if err != nil {
		removeErr, cleanupSyncErr := cleanupPublished()
		return VerificationResult{}, fmt.Errorf("verify published observer stage: %w; cleanup remove=%v sync=%v", err, removeErr, cleanupSyncErr)
	}
	return verified, nil
}

func randomPrivateName(prefix string) (string, error) {
	var value [16]byte
	if _, err := io.ReadFull(rand.Reader, value[:]); err != nil {
		return "", fmt.Errorf("generate private stage name: %w", err)
	}
	return prefix + hex.EncodeToString(value[:]), nil
}

func syncOpenDirectory(directory *os.File) error {
	if directory == nil {
		return errors.New("directory handle is nil")
	}
	return directory.Sync()
}

func syncRootDirectory(root *os.Root) error {
	if root == nil {
		return errors.New("rooted directory handle is nil")
	}
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	if err := directory.Sync(); err != nil {
		_ = directory.Close()
		return err
	}
	return directory.Close()
}
