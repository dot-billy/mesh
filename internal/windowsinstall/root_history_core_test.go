package windowsinstall

import "testing"

func TestWindowsRootHistoryNamesAreCanonicalAndDisjoint(t *testing.T) {
	for _, version := range []uint64{1, 2, 999, ^uint64(0)} {
		live := windowsRootHistoryName(version)
		if parsed, err := windowsRootHistoryVersion(live); err != nil || parsed != version {
			t.Fatalf("live %q parsed=%d err=%v", live, parsed, err)
		}
		pending := windowsRootPendingName(version)
		if parsed, err := windowsRootPendingVersion(pending); err != nil || parsed != version {
			t.Fatalf("pending %q parsed=%d err=%v", pending, parsed, err)
		}
		if !isWindowsRootHistoryNamespace(live) || !isWindowsRootHistoryNamespace(pending) {
			t.Fatal("canonical root-history name escaped its namespace")
		}
	}
	for _, invalid := range []string{"root-1.update.json", "root-00000000000000000000.update.json", ".root-00000000000000000001.update.json", "root-x"} {
		if _, err := windowsRootHistoryVersion(invalid); err == nil {
			t.Fatalf("invalid live root-history name %q accepted", invalid)
		}
	}
}
