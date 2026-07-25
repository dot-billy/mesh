package windowsinstallercompat

import "testing"

func TestCurrentWindowsInstallerCompatibility(t *testing.T) {
	current, err := Current()
	if err != nil {
		t.Fatal(err)
	}
	if current != Supported() {
		t.Fatalf("current compatibility = %+v, want %+v", current, Supported())
	}
	if _, err := ParseIdentity(Identity + "x"); err == nil {
		t.Fatal("appended Windows compatibility frame was accepted")
	}
}
