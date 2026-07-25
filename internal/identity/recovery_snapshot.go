package identity

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
)

// ValidateRecoverySnapshot validates exact persisted identity-state bytes for
// offline recovery. Both supported schemas are accepted without migration or
// writes, and every sealed OIDC login payload is opened and validated with the
// supplied purpose-bound sealer. The input is never modified.
func ValidateRecoverySnapshot(raw []byte, sealer Sealer) error {
	_, err := validateRecoverySnapshot(raw, sealer)
	return err
}

// ExportRecoverySnapshot returns an exact, detached copy of the durable
// identity-state file. The process lock and store mutex remain held across the
// stable read, sealed-payload validation, and in-memory state comparison.
func (s *FileStore) ExportRecoverySnapshot(ctx context.Context) ([]byte, error) {
	if ctx == nil {
		return nil, errors.New("recovery snapshot context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.root == nil || s.lock == nil {
		return nil, ErrClosed
	}
	if err := s.ensureDurableLocked(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	raw, err := s.readRecoverySnapshotLocked()
	if err != nil {
		return nil, fmt.Errorf("read identity recovery snapshot: %w", err)
	}
	persisted, err := validateRecoverySnapshot(raw, s.sealer)
	if err != nil {
		return nil, fmt.Errorf("validate identity recovery snapshot: %w", err)
	}
	if !reflect.DeepEqual(persisted, s.state) {
		return nil, errors.New("persisted recovery snapshot does not match in-memory identity state")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return bytes.Clone(raw), nil
}

func validateRecoverySnapshot(raw []byte, sealer Sealer) (identityState, error) {
	if nilInterface(sealer) {
		return identityState{}, errors.New("identity recovery snapshot requires a purpose-bound sealer")
	}
	state, err := decodeIdentityStateDocument(raw, true)
	if err != nil {
		return identityState{}, err
	}
	validator := newIdentityOperations(nil, sealer)
	if err := validator.validateState(state); err != nil {
		return identityState{}, fmt.Errorf("validate identity state: %w", err)
	}
	return state, nil
}

func (s *FileStore) readRecoverySnapshotLocked() ([]byte, error) {
	before, err := s.root.Lstat(s.fileName)
	if err != nil {
		return nil, err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || before.Size() > maxIdentityStateSize {
		return nil, errors.New("identity state must be a bounded private regular file")
	}
	file, err := s.root.Open(s.fileName)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return nil, errors.New("identity state changed while opening")
	}
	if err := requirePrivateFile(file, opened); err != nil {
		return nil, fmt.Errorf("identity state: %w", err)
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxIdentityStateSize+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxIdentityStateSize {
		return nil, errors.New("identity state exceeds its size limit")
	}
	after, err := s.root.Lstat(s.fileName)
	if err != nil || !os.SameFile(opened, after) {
		return nil, errors.New("identity state changed during recovery snapshot read")
	}
	return raw, nil
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
