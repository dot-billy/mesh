//go:build !windows && !darwin

package nodeagent

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"mesh/internal/runtimetelemetry"
)

func validActiveProbeJournal() activeProbeJournal {
	age := uint64(12)
	return activeProbeJournal{
		Schema:     activeProbeJournalSchemaV1,
		PlanSHA256: strings.Repeat("a", 64),
		ReservedAt: time.Date(2026, 7, 20, 20, 1, 2, 0, time.UTC),
		Result: runtimetelemetry.ActiveProbeResult{
			Version: runtimetelemetry.ActiveProbeVersionV1, State: runtimetelemetry.ProbeAttempted,
			SampleAgeMS: &age, Attempted: 2, Replied: 1, DurationMS: 14,
		},
	}
}

func newActiveProbeJournalStore(t *testing.T) *StateStore {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := NewStateStore(filepath.Join(directory, "agent.json"))
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func TestActiveProbeJournalRoundTripsCanonicalPrivateBytes(t *testing.T) {
	store := newActiveProbeJournalStore(t)
	journal := validActiveProbeJournal()
	if err := store.SaveActiveProbeJournal(journal); err != nil {
		t.Fatalf("SaveActiveProbeJournal: %v", err)
	}
	path := store.Path() + ".runtime-probe.json"
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"schema":"mesh-agent-active-probe-journal-v1","plan_sha256":"` + strings.Repeat("a", 64) + `","reserved_at":"2026-07-20T20:01:02Z","result":{"version":1,"state":"attempted","sample_age_ms":12,"attempted":2,"replied":1,"duration_ms":14}}` + "\n"
	if string(raw) != want || len(raw) > maxActiveProbeJournalBytes {
		t.Fatalf("journal bytes = %q", raw)
	}
	info, err := os.Lstat(path)
	if err != nil || !privateRegularFile(info) || info.Mode().Perm() != 0o600 {
		t.Fatalf("journal metadata = %#v err=%v", info, err)
	}
	loaded, err := store.LoadActiveProbeJournal()
	if err != nil || !reflect.DeepEqual(loaded, journal) || loaded.Result.SampleAgeMS == journal.Result.SampleAgeMS {
		t.Fatalf("loaded journal = %#v err=%v", loaded, err)
	}
	*journal.Result.SampleAgeMS = 999
	if *loaded.Result.SampleAgeMS != 12 {
		t.Fatal("loaded journal aliases caller result memory")
	}
}

func TestActiveProbeJournalMissingFilePreservesNotExist(t *testing.T) {
	store := newActiveProbeJournalStore(t)
	if _, err := store.LoadActiveProbeJournal(); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing journal error = %v", err)
	}
}

func TestActiveProbeJournalRejectsInvalidValuesBeforeWriting(t *testing.T) {
	tests := map[string]func(*activeProbeJournal){
		"schema":         func(value *activeProbeJournal) { value.Schema = "mesh-agent-active-probe-journal-v2" },
		"uppercase hash": func(value *activeProbeJournal) { value.PlanSHA256 = strings.Repeat("A", 64) },
		"short hash":     func(value *activeProbeJournal) { value.PlanSHA256 = strings.Repeat("a", 63) },
		"local time": func(value *activeProbeJournal) {
			value.ReservedAt = value.ReservedAt.In(time.FixedZone("offset", 3600))
		},
		"zero time":      func(value *activeProbeJournal) { value.ReservedAt = time.Time{} },
		"invalid result": func(value *activeProbeJournal) { value.Result.Attempted = 9 },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			store := newActiveProbeJournalStore(t)
			journal := validActiveProbeJournal()
			mutate(&journal)
			if err := store.SaveActiveProbeJournal(journal); err == nil {
				t.Fatal("invalid journal was saved")
			}
			if _, err := os.Lstat(store.Path() + ".runtime-probe.json"); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("invalid save created a journal: %v", err)
			}
		})
	}
}

func TestActiveProbeJournalRejectsNoncanonicalOrUnsafeExistingFile(t *testing.T) {
	canonical := `{"schema":"mesh-agent-active-probe-journal-v1","plan_sha256":"` + strings.Repeat("a", 64) + `","reserved_at":"2026-07-20T20:01:02Z","result":{"version":1,"state":"unsupported","sample_age_ms":null,"attempted":0,"replied":0,"duration_ms":0}}` + "\n"
	tests := map[string][]byte{
		"missing newline": []byte(strings.TrimSuffix(canonical, "\n")),
		"extra newline":   []byte(canonical + "\n"),
		"leading space":   []byte(" " + canonical),
		"unknown field":   []byte(`{"schema":"mesh-agent-active-probe-journal-v1","plan_sha256":"` + strings.Repeat("a", 64) + `","reserved_at":"2026-07-20T20:01:02Z","result":{"version":1,"state":"unsupported","sample_age_ms":null,"attempted":0,"replied":0,"duration_ms":0},"extra":true}` + "\n"),
		"duplicate field": []byte(`{"schema":"mesh-agent-active-probe-journal-v1","schema":"mesh-agent-active-probe-journal-v1","plan_sha256":"` + strings.Repeat("a", 64) + `","reserved_at":"2026-07-20T20:01:02Z","result":{"version":1,"state":"unsupported","sample_age_ms":null,"attempted":0,"replied":0,"duration_ms":0}}` + "\n"),
		"trailing value":  []byte(strings.TrimSuffix(canonical, "\n") + `{}` + "\n"),
		"oversized":       bytes.Repeat([]byte{'x'}, maxActiveProbeJournalBytes+1),
	}
	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			store := newActiveProbeJournalStore(t)
			path := store.Path() + ".runtime-probe.json"
			if err := os.WriteFile(path, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := store.LoadActiveProbeJournal(); err == nil {
				t.Fatal("invalid existing journal was loaded")
			}
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := store.SaveActiveProbeJournal(validActiveProbeJournal()); err == nil {
				t.Fatal("invalid existing journal was overwritten")
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(after, before) {
				t.Fatalf("invalid existing bytes changed: err=%v before=%q after=%q", err, before, after)
			}
		})
	}
}

func TestActiveProbeJournalRejectsSymlinkNonregularAndInsecureMetadata(t *testing.T) {
	t.Run("symlink", func(t *testing.T) {
		store := newActiveProbeJournalStore(t)
		target := filepath.Join(filepath.Dir(store.Path()), "target")
		if err := os.WriteFile(target, []byte("preserve"), 0o600); err != nil {
			t.Fatal(err)
		}
		path := store.Path() + ".runtime-probe.json"
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
		if _, err := store.LoadActiveProbeJournal(); err == nil {
			t.Fatal("symlink journal was loaded")
		}
		if err := store.SaveActiveProbeJournal(validActiveProbeJournal()); err == nil {
			t.Fatal("symlink journal was replaced")
		}
		raw, _ := os.ReadFile(target)
		if string(raw) != "preserve" {
			t.Fatalf("symlink target changed: %q", raw)
		}
	})

	for _, test := range []struct {
		name  string
		setup func(string) error
	}{
		{name: "directory", setup: func(path string) error { return os.Mkdir(path, 0o700) }},
		{name: "insecure mode", setup: func(path string) error { return os.WriteFile(path, []byte("{}\n"), 0o640) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := newActiveProbeJournalStore(t)
			path := store.Path() + ".runtime-probe.json"
			if err := test.setup(path); err != nil {
				t.Fatal(err)
			}
			if _, err := store.LoadActiveProbeJournal(); err == nil {
				t.Fatal("unsafe journal was loaded")
			}
			if err := store.SaveActiveProbeJournal(validActiveProbeJournal()); err == nil {
				t.Fatal("unsafe journal was replaced")
			}
		})
	}
}

func TestActiveProbeJournalAtomicallyReplacesOnlyValidExistingState(t *testing.T) {
	store := newActiveProbeJournalStore(t)
	first := validActiveProbeJournal()
	first.Result = runtimetelemetry.UnsupportedActiveProbe()
	if err := store.SaveActiveProbeJournal(first); err != nil {
		t.Fatal(err)
	}
	second := validActiveProbeJournal()
	second.PlanSHA256 = strings.Repeat("b", 64)
	second.ReservedAt = second.ReservedAt.Add(time.Minute)
	if err := store.SaveActiveProbeJournal(second); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.LoadActiveProbeJournal()
	if err != nil || !reflect.DeepEqual(loaded, second) {
		t.Fatalf("replaced journal = %#v err=%v", loaded, err)
	}
	entries, err := os.ReadDir(filepath.Dir(store.Path()))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".mesh-private-") {
			t.Fatalf("atomic journal temporary file remained: %s", entry.Name())
		}
	}
}
