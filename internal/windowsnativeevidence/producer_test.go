package windowsnativeevidence

import (
	"bufio"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestPowerShellProducerSourceInventoriesMatchVerifier(t *testing.T) {
	repository, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		path, marker string
		want         []string
	}{
		{path: "scripts/windows-bootstrap-verifier-smoke.ps1", marker: "$sourceFiles = @(", want: bootstrapSources},
		{path: "scripts/windows-native-runtime-smoke.ps1", marker: "$testFiles = @(", want: runtimeSources},
	} {
		t.Run(filepath.Base(test.path), func(t *testing.T) {
			got := parsePowerShellStringArray(t, filepath.Join(repository, test.path), test.marker)
			want := append([]string(nil), test.want...)
			sort.Strings(want)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("producer source inventory = %q, verifier expects %q", got, want)
			}
		})
	}
}

func parsePowerShellStringArray(t *testing.T, path, marker string) []string {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	found := false
	var values []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !found {
			found = line == marker
			continue
		}
		if line == ")" {
			break
		}
		line = strings.TrimSuffix(line, ",")
		if len(line) < 2 || line[0] != '"' || line[len(line)-1] != '"' {
			t.Fatalf("nonliteral source entry %q", line)
		}
		values = append(values, strings.ReplaceAll(line[1:len(line)-1], `\`, "/"))
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if !found || len(values) == 0 {
		t.Fatalf("PowerShell array %q not found", marker)
	}
	sort.Strings(values)
	return values
}
