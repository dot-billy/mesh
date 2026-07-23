package backupio

import (
	"context"
	"errors"
	"time"
)

const (
	ControlStateName  = "state.json"
	IdentityStateName = "identity-state.json"
	MasterKeyName     = "master.key"
	AdminTokenName    = "admin.token"
	ReceiptName       = ".mesh-restore-receipt.json"

	RestoreMarkerSchema  = "mesh-restore-marker-v1"
	RestoreReceiptSchema = "mesh-restore-receipt-v1"
)

var (
	ErrUnsupported       = errors.New("backup operations are not supported on this platform")
	ErrVerifyRequired    = errors.New("backup publication may be durable; verify the final archive before retrying")
	ErrUnsafeSnapshot    = errors.New("backup source stability could not be proved")
	ErrIncompleteRestore = errors.New("an incomplete Mesh restore requires operator attention")
	ErrStartupFenceBusy  = errors.New("restore or server startup already holds the parent-directory fence")
)

type KeygenOptions struct {
	OutputPath string
}

type KeygenResult struct {
	Schema string `json:"schema"`
	Status string `json:"status"`
	Path   string `json:"path"`
}

type CreateOptions struct {
	DataDir    string
	KeyFile    string
	OutputPath string
	MasterKey  string
	AdminToken string
	Now        func() time.Time
}

type ArchiveOptions struct {
	KeyFile     string
	ArchivePath string
}

type RestoreOptions struct {
	KeyFile          string
	ArchivePath      string
	TargetDir        string
	ExpectedBackupID string
	Now              func() time.Time
}

type FinalizeRestoreOptions struct {
	TargetDir string
	Now       func() time.Time
}

type ArchiveResult struct {
	Schema      string    `json:"schema"`
	Status      string    `json:"status"`
	BackupID    string    `json:"backup_id"`
	CreatedAt   time.Time `json:"created_at"`
	ArchivePath string    `json:"archive_path,omitempty"`
	TargetDir   string    `json:"target_dir,omitempty"`
	OperationID string    `json:"operation_id,omitempty"`
}

// Operations is the filesystem-facing backup command surface. Implementations
// are intentionally unavailable on platforms where owner-only path and
// directory durability guarantees cannot be established.
type Operations interface {
	Keygen(KeygenOptions) (KeygenResult, error)
	Create(context.Context, CreateOptions) (ArchiveResult, error)
	Inspect(context.Context, ArchiveOptions) (ArchiveResult, error)
	Verify(context.Context, ArchiveOptions) (ArchiveResult, error)
	Restore(context.Context, RestoreOptions) (ArchiveResult, error)
	FinalizeRestore(context.Context, FinalizeRestoreOptions) (ArchiveResult, error)
}

func New() Operations { return newOperations() }
