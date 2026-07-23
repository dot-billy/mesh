//go:build !linux

package backupio

import (
	"context"
	"errors"
	"testing"
)

func TestUnsupportedPlatformOperationsFailClosed(t *testing.T) {
	operations := New()
	if _, err := operations.Keygen(KeygenOptions{}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("keygen error = %v", err)
	}
	if _, err := operations.Create(context.Background(), CreateOptions{}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("create error = %v", err)
	}
	if _, err := operations.Inspect(context.Background(), ArchiveOptions{}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("inspect error = %v", err)
	}
	if _, err := operations.Verify(context.Background(), ArchiveOptions{}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("verify error = %v", err)
	}
	if _, err := operations.Restore(context.Background(), RestoreOptions{}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("restore error = %v", err)
	}
	if _, err := operations.FinalizeRestore(context.Background(), FinalizeRestoreOptions{}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("finalize error = %v", err)
	}
}
