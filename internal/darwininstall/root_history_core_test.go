package darwininstall

import "testing"

func TestDarwinRootHistoryNamesAreCanonicalAndDisjoint(t *testing.T) {
	for _, version := range []uint64{1, 42, ^uint64(0)} {
		live := darwinRootHistoryName(version)
		parsed, err := darwinRootHistoryVersion(live)
		if err != nil || parsed != version {
			t.Fatalf("live root-history name %q parsed as %d, %v", live, parsed, err)
		}
		pending := darwinRootPendingName(version)
		parsed, err = darwinRootPendingVersion(pending)
		if err != nil || parsed != version {
			t.Fatalf("pending root-history name %q parsed as %d, %v", pending, parsed, err)
		}
		if !isDarwinRootHistoryNamespace(live) || !isDarwinRootHistoryNamespace(pending) {
			t.Fatal("canonical root-history name escaped its reserved namespace")
		}
	}
	for _, name := range []string{
		"root-1.update.json", "root-00000000000000000000.update.json",
		"root-00000000000000000001.update.json.new", ".root-00000000000000000001.update.json",
	} {
		if _, err := darwinRootHistoryVersion(name); err == nil {
			t.Fatalf("noncanonical live name %q was accepted", name)
		}
		if _, err := darwinRootPendingVersion(name); err == nil {
			t.Fatalf("noncanonical pending name %q was accepted", name)
		}
	}
}
