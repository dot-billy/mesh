package darwinnativeevidence

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestInspectAndMatchFullNativeEvidence(t *testing.T) {
	directory := t.TempDir()
	system := []byte("ProductName:\tmacOS\ngo_version=go version go1.26.5 darwin/arm64\n")
	tests := []byte("PASS\n")
	source := fixtureSourceInventory()
	receipt := fixtureReceipt(true, system, tests, source)
	for name, content := range map[string][]byte{
		"receipt.txt": receipt, "source.txt": source, "system.txt": system, "tests.txt": tests,
	} {
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, content, 0o400); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o400); err != nil {
			t.Fatal(err)
		}
	}
	evidence, err := InspectDirectory(directory)
	if err != nil {
		t.Fatal(err)
	}
	if err := evidence.MatchFull(time.Date(2026, 7, 21, 22, 0, 0, 0, time.UTC), "arm64", strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	if err := evidence.MatchFull(time.Date(2026, 7, 23, 0, 0, 1, 0, time.UTC), "arm64", strings.Repeat("a", 64)); err == nil || !strings.Contains(err.Error(), "older than 24 hours") {
		t.Fatalf("stale evidence returned %v", err)
	}
}

func TestNativeEvidenceRejectsPartialAndDrift(t *testing.T) {
	system, tests, source := []byte("system\n"), []byte("tests\n"), fixtureSourceInventory()
	partial, err := ParseReceipt(fixtureReceipt(false, system, tests, source))
	if err != nil {
		t.Fatal(err)
	}
	if err := (Evidence{Receipt: partial}).MatchFull(time.Date(2026, 7, 21, 22, 0, 0, 0, time.UTC), "arm64", strings.Repeat("a", 64)); err == nil || !strings.Contains(err.Error(), "omitted system launchctl") {
		t.Fatalf("partial native evidence returned %v", err)
	}
	if _, err := ParseReceipt(append([]byte(" "), fixtureReceipt(true, system, tests, source)...)); err == nil {
		t.Fatal("noncanonical native receipt was accepted")
	}
	drifted := append([]byte(nil), source...)
	drifted[len(drifted)/2] ^= 1
	if err := validateSourceInventory(drifted); err == nil {
		t.Fatal("drifted source inventory was accepted")
	}
}

func TestBashProducerSourceInventoryMatchesVerifier(t *testing.T) {
	repository, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(filepath.Join(repository, "scripts", "darwin-native-runtime-smoke.sh"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	found := false
	var got []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !found {
			found = line == "source_paths=("
			continue
		}
		if line == ")" {
			break
		}
		if line == "" || strings.ContainsAny(line, " \t\"'") {
			t.Fatalf("noncanonical source path literal %q", line)
		}
		got = append(got, line)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	want := append([]string(nil), sourcePaths...)
	sort.Strings(got)
	sort.Strings(want)
	if !found || !reflect.DeepEqual(got, want) {
		t.Fatalf("producer source paths = %q, verifier expects %q", got, want)
	}
}

func fixtureReceipt(full bool, system, tests, source []byte) []byte {
	gate := "0"
	if full {
		gate = "1"
	}
	return []byte(strings.Join([]string{
		"schema=" + Schema,
		"architecture=arm64",
		"system_launchctl_mutation_test=" + gate,
		"system_launchctl_proof_label=" + ProofLabel,
		"darwin_bundle_sha256=" + strings.Repeat("a", 64),
		"system_sha256=" + digest(system),
		"tests_sha256=" + digest(tests),
		"source_sha256=" + digest(source),
		"started_at=2026-07-21T21:00:00Z",
		"verified_at=2026-07-21T21:30:00Z",
	}, "\n") + "\n")
}

func fixtureSourceInventory() []byte {
	names := append([]string(nil), sourcePaths...)
	sort.Strings(names)
	var output strings.Builder
	for _, name := range names {
		output.WriteString(strings.Repeat("1", 64))
		output.WriteString("  ")
		output.WriteString(name)
		output.WriteByte('\n')
	}
	return []byte(output.String())
}

func digest(raw []byte) string {
	value := sha256.Sum256(raw)
	return hex.EncodeToString(value[:])
}
