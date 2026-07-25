package nebulaobserverartifact

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	observerassets "mesh/third_party/nebula-observer"
)

func TestEmbeddedPolicyIsCanonicalAndValid(t *testing.T) {
	policy, digest, err := EmbeddedPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if policy.Schema != policySchema || !lowerHex(digest) {
		t.Fatalf("unexpected embedded policy identity: schema=%q digest=%q", policy.Schema, digest)
	}
	for _, target := range policy.Targets {
		for _, entry := range target.Entries {
			if entry.Size <= 1 || entry.SHA256 == string(bytes.Repeat([]byte("0"), 64)) {
				t.Fatalf("observer output is not fully locked: %+v", entry)
			}
		}
	}
	policy.BuildFlags[0] = "changed"
	policy.SecurityDependencies[0].Version = "changed"
	again, _, err := EmbeddedPolicy()
	if err != nil || again.BuildFlags[0] != lockedBuildFlags[0] || again.SecurityDependencies[0] != lockedSecurityDependencies[0] {
		t.Fatalf("mutating returned policy changed embedded state: policy=%+v err=%v", again, err)
	}
}

func TestParsePolicyRejectsUnknownAndNoncanonicalInput(t *testing.T) {
	raw := observerassets.BuildLock()
	unknown := bytes.Replace(raw, []byte("{\n"), []byte("{\n  \"unknown\": true,\n"), 1)
	if _, err := ParsePolicy(unknown); err == nil {
		t.Fatal("observer policy accepted an unknown field")
	}
	compact := bytes.ReplaceAll(raw, []byte("  "), nil)
	if _, err := ParsePolicy(compact); err == nil {
		t.Fatal("observer policy accepted noncanonical formatting")
	}
}

func TestLayeredPlatformPoliciesBindExactTargets(t *testing.T) {
	for name, load := range map[string]func() ([]TargetLock, string, error){
		"darwin": func() ([]TargetLock, string, error) {
			policy, digest, err := embeddedDarwinPolicy()
			return policy.Targets, digest, err
		},
		"windows": func() ([]TargetLock, string, error) {
			policy, digest, err := embeddedWindowsPolicy()
			return policy.Targets, digest, err
		},
	} {
		t.Run(name, func(t *testing.T) {
			targets, digest, err := load()
			if err != nil || !lowerHex(digest) || len(targets) != 2 {
				t.Fatalf("invalid layered policy: targets=%+v digest=%q err=%v", targets, digest, err)
			}
			for index, arch := range []string{"amd64", "arm64"} {
				if targets[index].OS != name || targets[index].Arch != arch || len(targets[index].Entries) != 2 {
					t.Fatalf("unexpected target %d: %+v", index, targets[index])
				}
			}
			targets[0].Entries[0].SHA256 = strings.Repeat("0", 64)
			again, _, err := load()
			if err != nil || again[0].Entries[0].SHA256 == strings.Repeat("0", 64) {
				t.Fatalf("mutating returned policy changed embedded state: targets=%+v err=%v", again, err)
			}
		})
	}
}

func TestSourceTreeDigestBindsPathsContentAndExecutableBits(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "nested")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(directory, "source.go")
	if err := os.WriteFile(file, []byte("package sample\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	first, _, _, err := hashSourceTree(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(file, 0o400); err != nil {
		t.Fatal(err)
	}
	second, _, _, err := hashSourceTree(root)
	if err != nil || second != first {
		t.Fatalf("ordinary write-bit change affected canonical tree digest: first=%s second=%s err=%v", first, second, err)
	}
	if err := os.Chmod(file, 0o500); err != nil {
		t.Fatal(err)
	}
	executable, _, _, err := hashSourceTree(root)
	if err != nil || executable == first {
		t.Fatalf("executable-bit change was not bound: first=%s executable=%s err=%v", first, executable, err)
	}
	if err := os.Chmod(file, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("package changed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	changed, _, _, err := hashSourceTree(root)
	if err != nil || changed == first {
		t.Fatalf("content change was not bound: first=%s changed=%s err=%v", first, changed, err)
	}
	if err := os.Symlink(file, filepath.Join(root, "linked")); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := hashSourceTree(root); err == nil {
		t.Fatal("source tree accepted a symbolic link")
	}
}

func TestBuildRejectsExistingOutputBeforeSourceWork(t *testing.T) {
	if _, err := Build(context.Background(), "amd64", t.TempDir()); err == nil {
		t.Fatal("observer builder accepted an existing output directory")
	}
	if _, err := BuildWindows(context.Background(), "amd64", t.TempDir()); err == nil {
		t.Fatal("Windows runtime builder accepted an existing output directory")
	}
	if _, err := BuildDarwin(context.Background(), "amd64", t.TempDir()); err == nil {
		t.Fatal("Darwin runtime builder accepted an existing output directory")
	}
}
