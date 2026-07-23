//go:build darwin

package darwininstall

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"mesh/internal/nodeagent"

	"golang.org/x/sys/unix"
)

const (
	ProductionDarwinIntakeRecordPath = ProductionStateDirectory + "/intake.json"
	darwinIntakeRecordName           = "intake.json"
	darwinIntakeRecordPendingName    = ".intake.json.new"
	darwinIntakeRecordFileMode       = uint16(0o400)
)

type darwinIntakeRecordSnapshot struct {
	found    bool
	raw      []byte
	record   DarwinIntakeRecord
	identity darwinInstallStatSnapshot
}

func (lock *InstallerJournalLock) LoadIntakeRecord() (DarwinIntakeRecord, bool, error) {
	if err := lock.validateHeld(); err != nil {
		return DarwinIntakeRecord{}, false, err
	}
	if lock.intakeLoaded {
		return DarwinIntakeRecord{}, false, errors.New("Darwin installer lock already loaded an accepted-intake snapshot")
	}
	if err := lock.reconcileIntakeRecordPending(); err != nil {
		return DarwinIntakeRecord{}, false, err
	}
	snapshot, err := lock.readIntakeRecord(darwinIntakeRecordName)
	if err != nil {
		return DarwinIntakeRecord{}, false, err
	}
	stable, err := lock.readIntakeRecord(darwinIntakeRecordName)
	if err != nil || !sameDarwinIntakeRecordSnapshot(snapshot, stable) {
		return DarwinIntakeRecord{}, false, errors.Join(err, errors.New("Darwin accepted intake changed while loading"))
	}
	lock.intakeLoaded = true
	lock.intakeSnapshot = snapshot
	return snapshot.record, snapshot.found, nil
}

func (lock *InstallerJournalLock) CommitIntakeRecord(record DarwinIntakeRecord) error {
	if err := lock.validateHeld(); err != nil {
		return err
	}
	if !lock.intakeLoaded {
		return errors.New("Darwin accepted intake must be loaded before commit")
	}
	current, err := lock.readIntakeRecord(darwinIntakeRecordName)
	if err != nil {
		return err
	}
	if !sameDarwinIntakeRecordSnapshot(lock.intakeSnapshot, current) {
		return errors.New("Darwin accepted intake changed after its locked snapshot")
	}
	raw, err := encodeDarwinIntakeRecord(record)
	if err != nil {
		return err
	}
	if current.found {
		if bytes.Equal(current.raw, raw) {
			return nil
		}
		return errors.New("an unrelated Darwin accepted intake is already active")
	}
	pending, err := lock.readIntakeRecordRaw(darwinIntakeRecordPendingName)
	if err != nil {
		return err
	}
	if pending.found {
		return errors.New("Darwin accepted-intake pending publication was not reconciled")
	}
	if err := lock.writeIntakeRecordPending(raw); err != nil {
		return err
	}
	currentAgain, err := lock.readIntakeRecord(darwinIntakeRecordName)
	if err != nil || !sameDarwinIntakeRecordSnapshot(lock.intakeSnapshot, currentAgain) {
		return errors.Join(err, errors.New("Darwin accepted intake changed while preparing publication"))
	}
	if err := unix.RenameatxNp(lock.directory.fd, darwinIntakeRecordPendingName, lock.directory.fd, darwinIntakeRecordName, unix.RENAME_EXCL); err != nil {
		return err
	}
	if err := lock.directory.directory.Sync(); err != nil {
		return err
	}
	committed, err := lock.readIntakeRecord(darwinIntakeRecordName)
	if err != nil || !committed.found || !bytes.Equal(committed.raw, raw) {
		return errors.Join(err, errors.New("committed Darwin accepted intake differs after directory sync"))
	}
	lock.intakeSnapshot = committed
	return nil
}

func (lock *InstallerJournalLock) ClearIntakeRecord(expected DarwinIntakeRecord) error {
	if err := lock.validateHeld(); err != nil {
		return err
	}
	if !lock.intakeLoaded || !lock.intakeSnapshot.found {
		return errors.New("Darwin accepted intake is not loaded for clear")
	}
	want, err := encodeDarwinIntakeRecord(expected)
	if err != nil {
		return err
	}
	current, err := lock.readIntakeRecord(darwinIntakeRecordName)
	if err != nil {
		return err
	}
	if !sameDarwinIntakeRecordSnapshot(lock.intakeSnapshot, current) || !bytes.Equal(current.raw, want) {
		return errors.New("Darwin accepted intake changed before clear")
	}
	pending, err := lock.readIntakeRecordRaw(darwinIntakeRecordPendingName)
	if err != nil {
		return err
	}
	if pending.found {
		return errors.New("Darwin accepted-intake pending publication exists before clear")
	}
	if err := unix.Unlinkat(lock.directory.fd, darwinIntakeRecordName, 0); err != nil {
		return err
	}
	if err := lock.directory.directory.Sync(); err != nil {
		return err
	}
	after, err := lock.readIntakeRecordRaw(darwinIntakeRecordName)
	if err != nil || after.found {
		return errors.Join(err, errors.New("cleared Darwin accepted intake remains visible"))
	}
	lock.intakeSnapshot = darwinIntakeRecordSnapshot{}
	return nil
}

func (lock *InstallerJournalLock) reconcileIntakeRecordPending() error {
	pending, err := lock.readIntakeRecordRaw(darwinIntakeRecordPendingName)
	if err != nil || !pending.found {
		return err
	}
	if _, err := decodeDarwinIntakeRecord(pending.raw); err != nil {
		return fmt.Errorf("pending Darwin accepted intake is invalid and was preserved: %w", err)
	}
	live, err := lock.readIntakeRecordRaw(darwinIntakeRecordName)
	if err != nil {
		return err
	}
	if live.found {
		return errors.New("Darwin accepted intake has ambiguous live and pending records")
	}
	stable, err := lock.readIntakeRecordRaw(darwinIntakeRecordPendingName)
	if err != nil || !sameDarwinIntakeRecordSnapshot(pending, stable) {
		return errors.Join(err, errors.New("pending Darwin accepted intake changed during recovery"))
	}
	if err := unix.RenameatxNp(lock.directory.fd, darwinIntakeRecordPendingName, lock.directory.fd, darwinIntakeRecordName, unix.RENAME_EXCL); err != nil {
		return err
	}
	return lock.directory.directory.Sync()
}

func (lock *InstallerJournalLock) writeIntakeRecordPending(raw []byte) (returnErr error) {
	fd, err := unix.Openat(lock.directory.fd, darwinIntakeRecordPendingName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NOFOLLOW_ANY, uint32(darwinIntakeRecordFileMode))
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), filepath.Join(lock.store.directory, darwinIntakeRecordPendingName))
	if file == nil {
		_ = unix.Close(fd)
		return errors.New("adopt Darwin accepted-intake pending descriptor")
	}
	open := true
	defer func() {
		if open {
			returnErr = errors.Join(returnErr, file.Close())
		}
	}()
	if err := unix.Fchown(fd, 0, 0); err != nil {
		return err
	}
	if err := unix.Fchmod(fd, uint32(darwinIntakeRecordFileMode)); err != nil {
		return err
	}
	written, writeErr := file.Write(raw)
	if writeErr != nil || written != len(raw) {
		return errors.Join(writeErr, shortWriteError(written, len(raw)))
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		open = false
		return err
	}
	open = false
	pending, err := lock.readIntakeRecordRaw(darwinIntakeRecordPendingName)
	if err != nil || !pending.found || !bytes.Equal(pending.raw, raw) {
		return errors.Join(err, errors.New("Darwin accepted-intake pending bytes differ after write and sync"))
	}
	return nil
}

func (lock *InstallerJournalLock) readIntakeRecord(name string) (darwinIntakeRecordSnapshot, error) {
	raw, err := lock.readIntakeRecordRaw(name)
	if err != nil || !raw.found {
		return raw, err
	}
	record, err := decodeDarwinIntakeRecord(raw.raw)
	if err != nil {
		return darwinIntakeRecordSnapshot{}, err
	}
	raw.record = record
	return raw, nil
}

func (lock *InstallerJournalLock) readIntakeRecordRaw(name string) (result darwinIntakeRecordSnapshot, returnErr error) {
	var visibleBefore unix.Stat_t
	if err := unix.Fstatat(lock.directory.fd, name, &visibleBefore, unix.AT_SYMLINK_NOFOLLOW); errors.Is(err, unix.ENOENT) {
		return result, nil
	} else if err != nil {
		return result, err
	}
	if err := validateDarwinIntakeRecordStat(visibleBefore); err != nil {
		return result, fmt.Errorf("Darwin accepted-intake file %q: %w", name, err)
	}
	path := filepath.Join(lock.store.directory, name)
	if err := nodeagent.InspectDarwinSensitivePath(path); err != nil {
		return result, err
	}
	fd, err := unix.Openat(lock.directory.fd, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NOFOLLOW_ANY|unix.O_NONBLOCK, 0)
	if err != nil {
		return result, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return result, errors.New("adopt Darwin accepted-intake descriptor")
	}
	defer func() { returnErr = errors.Join(returnErr, file.Close()) }()
	var openedBefore, openedAfter, visibleAfter unix.Stat_t
	if err := unix.Fstat(fd, &openedBefore); err != nil {
		return result, err
	}
	raw, err := io.ReadAll(io.LimitReader(file, int64(maximumDarwinIntakeRecordSize)+1))
	if err != nil || len(raw) == 0 || len(raw) > maximumDarwinIntakeRecordSize {
		return result, errors.Join(err, errors.New("Darwin accepted intake changed or exceeded its bound while reading"))
	}
	if err := unix.Fstat(fd, &openedAfter); err != nil {
		return result, err
	}
	if err := unix.Fstatat(lock.directory.fd, name, &visibleAfter, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return result, err
	}
	for _, stat := range []unix.Stat_t{openedBefore, openedAfter, visibleAfter} {
		if err := validateDarwinIntakeRecordStat(stat); err != nil {
			return result, err
		}
	}
	identity := snapshotDarwinInstallStat(visibleBefore)
	if identity != snapshotDarwinInstallStat(openedBefore) || identity != snapshotDarwinInstallStat(openedAfter) || identity != snapshotDarwinInstallStat(visibleAfter) {
		return result, errors.New("Darwin accepted intake changed while reading")
	}
	if err := nodeagent.InspectDarwinSensitivePath(path); err != nil {
		return result, err
	}
	return darwinIntakeRecordSnapshot{found: true, raw: raw, identity: identity}, nil
}

func validateDarwinIntakeRecordStat(stat unix.Stat_t) error {
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o7777 != darwinIntakeRecordFileMode || stat.Uid != 0 || stat.Gid != 0 ||
		stat.Nlink != 1 || stat.Flags != 0 || stat.Size < 1 || stat.Size > int64(maximumDarwinIntakeRecordSize) {
		return errors.New("must be exact root:wheel, single-link, mode-0400, flag-free, and within its size bound")
	}
	return nil
}

func sameDarwinIntakeRecordSnapshot(left, right darwinIntakeRecordSnapshot) bool {
	if left.found != right.found {
		return false
	}
	return !left.found || left.identity == right.identity && bytes.Equal(left.raw, right.raw)
}
