package runtimetelemetry

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

var ErrUncertainCommit = errors.New("runtime telemetry commit durability is uncertain")

type FileStore struct {
	mu                sync.Mutex
	root              *os.Root
	lock              *os.File
	fileName          string
	state             State
	durabilityPending bool
	closed            bool
}

var _ Store = (*FileStore)(nil)

func OpenFileStore(path string) (*FileStore, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Base(path) == "." || filepath.Base(path) == string(filepath.Separator) || len(filepath.Base(path)) > 128 {
		return nil, fmt.Errorf("%w: telemetry state path must be a clean absolute file path", ErrInvalid)
	}
	directory, fileName := filepath.Dir(path), filepath.Base(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, fmt.Errorf("create runtime telemetry directory: %w", err)
	}
	directoryInfo, err := os.Lstat(directory)
	if err != nil || directoryInfo.Mode()&os.ModeSymlink != 0 || !directoryInfo.IsDir() || directoryInfo.Mode().Perm() != 0o700 || !ownedByCurrentUser(directoryInfo) {
		return nil, errors.New("runtime telemetry directory must be a real owner-only directory")
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, fmt.Errorf("open runtime telemetry directory: %w", err)
	}
	store := &FileStore{root: root, fileName: fileName}
	if err := store.openLock(); err != nil {
		root.Close()
		return nil, err
	}
	raw, err := store.readStateFile()
	switch {
	case errors.Is(err, os.ErrNotExist):
		store.state = EmptyState()
		if err := store.persistLocked(store.state); err != nil {
			store.closeResources()
			return nil, fmt.Errorf("initialize runtime telemetry state: %w", err)
		}
	case err != nil:
		store.closeResources()
		return nil, err
	default:
		store.state, err = DecodeState(raw)
		if err != nil {
			store.closeResources()
			return nil, fmt.Errorf("decode runtime telemetry state: %w", err)
		}
		canonical, encodeErr := EncodeState(store.state)
		if encodeErr != nil {
			store.closeResources()
			return nil, fmt.Errorf("encode migrated runtime telemetry state: %w", encodeErr)
		}
		if !bytes.Equal(raw, canonical) {
			if err := store.persistLocked(store.state); err != nil {
				store.closeResources()
				return nil, fmt.Errorf("migrate runtime telemetry state: %w", err)
			}
		}
	}
	return store, nil
}

func (s *FileStore) openLock() error {
	lockName := "." + s.fileName + ".lock"
	if info, err := s.root.Lstat(lockName); err == nil {
		if !privateRegularFile(info) {
			return errors.New("runtime telemetry lock must be a private single-link regular file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect runtime telemetry lock: %w", err)
	}
	lock, err := s.root.OpenFile(lockName, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("open runtime telemetry lock: %w", err)
	}
	if err := lock.Chmod(0o600); err != nil {
		lock.Close()
		return fmt.Errorf("chmod runtime telemetry lock: %w", err)
	}
	opened, statErr := lock.Stat()
	pathInfo, pathErr := s.root.Lstat(lockName)
	if statErr != nil || pathErr != nil || !os.SameFile(opened, pathInfo) || !privateRegularFile(opened) {
		lock.Close()
		return errors.New("runtime telemetry lock identity or metadata is invalid")
	}
	if err := lockTelemetryFile(lock); err != nil {
		lock.Close()
		return fmt.Errorf("lock runtime telemetry state: %w", err)
	}
	s.lock = lock
	return nil
}

func (s *FileStore) Put(nodeID string, heartbeatSequence int64, receivedAt time.Time, observation Observation, activeProbe ActiveProbeResult) (Record, bool, error) {
	return s.PutWithRoute(nodeID, heartbeatSequence, receivedAt, observation, activeProbe, UnsupportedRouteOverlap())
}

func (s *FileStore) PutWithRoute(nodeID string, heartbeatSequence int64, receivedAt time.Time, observation Observation, activeProbe ActiveProbeResult, routeOverlap RouteOverlapResult) (Record, bool, error) {
	return s.PutWithDNS(nodeID, heartbeatSequence, receivedAt, observation, activeProbe, routeOverlap, UnsupportedEndpointDNS())
}

func (s *FileStore) PutWithDNS(nodeID string, heartbeatSequence int64, receivedAt time.Time, observation Observation, activeProbe ActiveProbeResult, routeOverlap RouteOverlapResult, endpointDNS EndpointDNSResult) (Record, bool, error) {
	return s.PutWithConfig(nodeID, heartbeatSequence, receivedAt, observation, activeProbe, routeOverlap, endpointDNS, "")
}

func (s *FileStore) PutWithConfig(nodeID string, heartbeatSequence int64, receivedAt time.Time, observation Observation, activeProbe ActiveProbeResult, routeOverlap RouteOverlapResult, endpointDNS EndpointDNSResult, appliedConfigSHA256 string) (Record, bool, error) {
	candidate, err := newCandidateRecord(nodeID, heartbeatSequence, receivedAt, observation, activeProbe, routeOverlap, endpointDNS, appliedConfigSHA256)
	if err != nil {
		return Record{}, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.readyLocked(); err != nil {
		return Record{}, false, err
	}
	next := cloneState(s.state)
	index := sort.Search(len(next.Records), func(index int) bool { return next.Records[index].NodeID >= nodeID })
	var previous *Record
	if index < len(next.Records) && next.Records[index].NodeID == nodeID {
		existing := next.Records[index]
		previous = &existing
	}
	accepted, changed, err := transitionRecord(previous, candidate)
	if err != nil || !changed {
		return accepted, changed, err
	}
	if index == len(next.Records) || next.Records[index].NodeID != nodeID {
		if len(next.Records) >= MaxRecords {
			return Record{}, false, ErrInvalid
		}
		next.Records = append(next.Records, Record{})
		copy(next.Records[index+1:], next.Records[index:])
	}
	next.Records[index] = cloneRecord(accepted)
	if err := s.persistLocked(next); err != nil {
		return Record{}, false, err
	}
	return cloneRecord(accepted), true, nil
}

func (s *FileStore) Get(nodeID string) (Record, bool, error) {
	if !nodeIDPattern.MatchString(nodeID) {
		return Record{}, false, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.readyLocked(); err != nil {
		return Record{}, false, err
	}
	index := sort.Search(len(s.state.Records), func(index int) bool { return s.state.Records[index].NodeID >= nodeID })
	if index == len(s.state.Records) || s.state.Records[index].NodeID != nodeID {
		return Record{}, false, nil
	}
	return cloneRecord(s.state.Records[index]), true, nil
}

func (s *FileStore) List() ([]Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.readyLocked(); err != nil {
		return nil, err
	}
	records := make([]Record, len(s.state.Records))
	for index := range s.state.Records {
		records[index] = cloneRecord(s.state.Records[index])
	}
	return records, nil
}

func (s *FileStore) Delete(nodeID string) (bool, error) {
	if !nodeIDPattern.MatchString(nodeID) {
		return false, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.readyLocked(); err != nil {
		return false, err
	}
	next := cloneState(s.state)
	index := sort.Search(len(next.Records), func(index int) bool { return next.Records[index].NodeID >= nodeID })
	if index == len(next.Records) || next.Records[index].NodeID != nodeID {
		return false, nil
	}
	copy(next.Records[index:], next.Records[index+1:])
	next.Records = next.Records[:len(next.Records)-1]
	if err := s.persistLocked(next); err != nil {
		return false, err
	}
	return true, nil
}

func (s *FileStore) CheckReadiness() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.readyLocked()
}

func (s *FileStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	var durabilityErr error
	if s.durabilityPending {
		durabilityErr = s.syncRoot()
	}
	s.closed = true
	return errors.Join(durabilityErr, s.closeResources())
}

func (s *FileStore) readyLocked() error {
	if s.closed || s.root == nil || s.lock == nil {
		return ErrClosed
	}
	if s.durabilityPending {
		if err := s.syncRoot(); err != nil {
			return fmt.Errorf("%w: %v", ErrUncertainCommit, err)
		}
		s.durabilityPending = false
	}
	return nil
}

func (s *FileStore) persistLocked(state State) error {
	raw, err := EncodeState(state)
	if err != nil {
		return err
	}
	var random [8]byte
	if _, err := io.ReadFull(rand.Reader, random[:]); err != nil {
		return errors.New("generate runtime telemetry temporary name failed")
	}
	temporary := "." + s.fileName + ".tmp-" + hex.EncodeToString(random[:])
	file, err := s.root.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("create runtime telemetry temporary file: %w", err)
	}
	removeTemporary := true
	defer func() {
		_ = file.Close()
		if removeTemporary {
			_ = s.root.Remove(temporary)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		return fmt.Errorf("chmod runtime telemetry temporary file: %w", err)
	}
	if _, err := io.Copy(file, bytes.NewReader(raw)); err != nil {
		return fmt.Errorf("write runtime telemetry temporary file: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync runtime telemetry temporary file: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close runtime telemetry temporary file: %w", err)
	}
	if err := s.root.Rename(temporary, s.fileName); err != nil {
		return fmt.Errorf("publish runtime telemetry state: %w", err)
	}
	removeTemporary = false
	s.state = cloneState(state)
	if err := s.syncRoot(); err != nil {
		s.durabilityPending = true
		return fmt.Errorf("%w: sync runtime telemetry directory: %v", ErrUncertainCommit, err)
	}
	s.durabilityPending = false
	return nil
}

func (s *FileStore) readStateFile() ([]byte, error) {
	before, err := s.root.Lstat(s.fileName)
	if err != nil {
		return nil, err
	}
	if !privateRegularFile(before) || before.Size() < 1 || before.Size() > MaxStateDocumentBytes {
		return nil, errors.New("runtime telemetry state must be a bounded private single-link regular file")
	}
	file, err := s.root.OpenFile(s.fileName, os.O_RDONLY, 0)
	if err != nil {
		return nil, fmt.Errorf("open runtime telemetry state: %w", err)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return nil, errors.New("runtime telemetry state changed while opening")
	}
	raw, err := io.ReadAll(io.LimitReader(file, MaxStateDocumentBytes+1))
	if err != nil || len(raw) > MaxStateDocumentBytes {
		return nil, errors.New("read runtime telemetry state failed or exceeded its bound")
	}
	afterFD, fdErr := file.Stat()
	afterPath, pathErr := s.root.Lstat(s.fileName)
	if fdErr != nil || pathErr != nil || !sameStableFile(opened, afterFD) || !sameStableFile(opened, afterPath) {
		return nil, errors.New("runtime telemetry state changed while reading")
	}
	return raw, nil
}

func (s *FileStore) syncRoot() error {
	directory, err := s.root.Open(".")
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func (s *FileStore) closeResources() error {
	var result error
	if s.lock != nil {
		result = errors.Join(result, unlockTelemetryFile(s.lock), s.lock.Close())
		s.lock = nil
	}
	if s.root != nil {
		result = errors.Join(result, s.root.Close())
		s.root = nil
	}
	return result
}

func cloneState(state State) State {
	copy := State{Schema: state.Schema, Records: make([]Record, len(state.Records))}
	for index := range state.Records {
		copy.Records[index] = cloneRecord(state.Records[index])
	}
	return copy
}

func sameStableFile(left, right os.FileInfo) bool {
	return left != nil && right != nil && os.SameFile(left, right) && left.Size() == right.Size() && left.ModTime().Equal(right.ModTime()) && left.Mode() == right.Mode()
}
