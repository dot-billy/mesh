//go:build !linux

package backupio

import "context"

// OpenValidatedImportArchive fails closed where the Linux filesystem security
// contract used by the offline archive reader cannot be established.
func OpenValidatedImportArchive(context.Context, ImportArchiveOptions) (*ValidatedImportArchive, error) {
	return nil, ErrUnsupported
}

// ValidateExactDocuments fails closed on unsupported platforms.
func (*ValidatedImportArchive) ValidateExactDocuments(context.Context, []byte, []byte) error {
	return ErrUnsupported
}
