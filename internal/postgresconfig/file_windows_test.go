//go:build windows

package postgresconfig

import "testing"

func TestWindowsFailsClosed(t *testing.T) {
	_, err := LoadFile(`C:\mesh\postgres.dsn`, Options{})
	requireStageWindows(t, err, StagePlatform)
}

func requireStageWindows(t *testing.T, err error, want Stage) {
	t.Helper()
	configErr, ok := err.(*Error)
	if !ok || configErr.Stage != want {
		t.Fatalf("got %v, want %s", err, want)
	}
}
