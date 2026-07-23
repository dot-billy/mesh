//go:build !linux

package backupio

import "context"

type unsupportedOperations struct{}

func newOperations() Operations { return unsupportedOperations{} }

func (unsupportedOperations) Keygen(KeygenOptions) (KeygenResult, error) {
	return KeygenResult{}, ErrUnsupported
}
func (unsupportedOperations) Create(context.Context, CreateOptions) (ArchiveResult, error) {
	return ArchiveResult{}, ErrUnsupported
}
func (unsupportedOperations) Inspect(context.Context, ArchiveOptions) (ArchiveResult, error) {
	return ArchiveResult{}, ErrUnsupported
}
func (unsupportedOperations) Verify(context.Context, ArchiveOptions) (ArchiveResult, error) {
	return ArchiveResult{}, ErrUnsupported
}
func (unsupportedOperations) Restore(context.Context, RestoreOptions) (ArchiveResult, error) {
	return ArchiveResult{}, ErrUnsupported
}
func (unsupportedOperations) FinalizeRestore(context.Context, FinalizeRestoreOptions) (ArchiveResult, error) {
	return ArchiveResult{}, ErrUnsupported
}
