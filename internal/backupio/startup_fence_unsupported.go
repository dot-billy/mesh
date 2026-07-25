//go:build !linux

package backupio

// StartupFence retains marker checks on platforms where restore operations are
// unavailable. No same-platform restore can race server startup because every
// mutating backup operation fails closed outside Linux.
type StartupFence struct{ dataDir string }

func AcquireStartupFence(dataDir string) (*StartupFence, error) {
	if _, err := RestoreMarkerPath(dataDir); err != nil {
		return nil, err
	}
	return &StartupFence{dataDir: dataDir}, nil
}

func (fence *StartupFence) Check() error { return RefuseIncompleteRestore(fence.dataDir) }

func (*StartupFence) Close() error { return nil }
