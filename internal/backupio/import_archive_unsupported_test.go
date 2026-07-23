//go:build !linux

package backupio

import (
	"context"
	"errors"
	"testing"
)

func TestOpenValidatedImportArchiveUnsupported(t *testing.T) {
	archive, err := OpenValidatedImportArchive(context.Background(), ImportArchiveOptions{})
	if archive != nil || !errors.Is(err, ErrUnsupported) {
		t.Fatalf("got archive=%v err=%v", archive != nil, err)
	}
}
