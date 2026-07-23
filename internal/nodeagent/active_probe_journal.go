package nodeagent

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"mesh/internal/runtimetelemetry"
)

const (
	activeProbeJournalSchemaV1 = "mesh-agent-active-probe-journal-v1"
	maxActiveProbeJournalBytes = 4 << 10
)

type activeProbeJournal struct {
	Schema     string                             `json:"schema"`
	PlanSHA256 string                             `json:"plan_sha256"`
	ReservedAt time.Time                          `json:"reserved_at"`
	Result     runtimetelemetry.ActiveProbeResult `json:"result"`
}

func (journal activeProbeJournal) validate() error {
	if journal.Schema != activeProbeJournalSchemaV1 {
		return errors.New("active probe journal schema is invalid")
	}
	if !validDigest(journal.PlanSHA256) {
		return errors.New("active probe journal plan digest is invalid")
	}
	if journal.ReservedAt.IsZero() || journal.ReservedAt.Location() != time.UTC {
		return errors.New("active probe journal reservation time must be UTC")
	}
	if err := runtimetelemetry.ValidateActiveProbe(journal.Result); err != nil {
		return fmt.Errorf("validate active probe journal result: %w", err)
	}
	return nil
}

func cloneActiveProbeJournal(journal activeProbeJournal) activeProbeJournal {
	journal.Result = runtimetelemetry.CloneActiveProbe(journal.Result)
	return journal
}

func encodeActiveProbeJournal(journal activeProbeJournal) ([]byte, error) {
	if err := journal.validate(); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(journal)
	if err != nil {
		return nil, fmt.Errorf("encode active probe journal: %w", err)
	}
	raw = append(raw, '\n')
	if len(raw) == 0 || len(raw) > maxActiveProbeJournalBytes {
		return nil, errors.New("active probe journal exceeds size limit")
	}
	return raw, nil
}

func (s *StateStore) LoadActiveProbeJournal() (activeProbeJournal, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := validatePrivateParent(s.path); err != nil {
		return activeProbeJournal{}, err
	}
	return loadActiveProbeJournal(s.path + ".runtime-probe.json")
}

func loadActiveProbeJournal(path string) (activeProbeJournal, error) {
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return activeProbeJournal{}, fmt.Errorf("inspect active probe journal: %w", err)
	}
	if !privateRegularFile(pathInfo) || pathInfo.Size() < 1 || pathInfo.Size() > maxActiveProbeJournalBytes {
		return activeProbeJournal{}, errors.New("active probe journal must be a private regular file within the size limit")
	}
	file, err := os.Open(path)
	if err != nil {
		return activeProbeJournal{}, fmt.Errorf("open active probe journal: %w", err)
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !os.SameFile(pathInfo, openedInfo) || !privateRegularFile(openedInfo) {
		return activeProbeJournal{}, errors.New("active probe journal identity or metadata changed while opening")
	}
	if err := validateOpenedPrivateFile(file, openedInfo); err != nil {
		return activeProbeJournal{}, fmt.Errorf("active probe journal: %w", err)
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxActiveProbeJournalBytes+1))
	if err != nil {
		return activeProbeJournal{}, fmt.Errorf("read active probe journal: %w", err)
	}
	if len(raw) < 1 || len(raw) > maxActiveProbeJournalBytes {
		return activeProbeJournal{}, errors.New("active probe journal exceeds size limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var journal activeProbeJournal
	if err := decoder.Decode(&journal); err != nil {
		return activeProbeJournal{}, fmt.Errorf("decode active probe journal: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return activeProbeJournal{}, fmt.Errorf("decode active probe journal: %w", err)
	}
	canonical, err := encodeActiveProbeJournal(journal)
	if err != nil {
		return activeProbeJournal{}, err
	}
	if !bytes.Equal(raw, canonical) {
		return activeProbeJournal{}, errors.New("active probe journal is not canonical")
	}
	return cloneActiveProbeJournal(journal), nil
}

func (s *StateStore) SaveActiveProbeJournal(journal activeProbeJournal) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := validatePrivateParent(s.path); err != nil {
		return err
	}
	journal = cloneActiveProbeJournal(journal)
	raw, err := encodeActiveProbeJournal(journal)
	if err != nil {
		return err
	}
	path := s.path + ".runtime-probe.json"
	if existing, err := loadActiveProbeJournal(path); err == nil {
		if reflect.DeepEqual(existing, journal) {
			return nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("refusing to replace invalid active probe journal: %w", err)
	}
	if err := writeAtomicPrivateFile(path, raw); err != nil {
		return fmt.Errorf("write active probe journal: %w", err)
	}
	if err := syncDir(filepath.Dir(path)); err != nil {
		return fmt.Errorf("sync active probe journal directory: %w", err)
	}
	return nil
}
