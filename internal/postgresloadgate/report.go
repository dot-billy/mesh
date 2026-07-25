package postgresloadgate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"sync"
	"time"
)

const ReportSchema = "mesh-postgres-load-soak-v1"

type OperationRecord struct {
	ID             string    `json:"id"`
	Stage          string    `json:"stage"`
	Kind           string    `json:"kind"`
	Replica        int       `json:"replica"`
	Method         string    `json:"method"`
	Path           string    `json:"path"`
	Write          bool      `json:"write"`
	Attempts       int       `json:"attempts"`
	ExpectedStatus int       `json:"expected_status"`
	Status         int       `json:"status"`
	StartedAt      time.Time `json:"started_at"`
	DurationMicros int64     `json:"duration_micros"`
	ResponseBytes  int       `json:"response_bytes"`
	ResponseSHA256 string    `json:"response_sha256"`
	ResourceID     string    `json:"resource_id,omitempty"`
	Error          string    `json:"error,omitempty"`
}

type operationLedger struct {
	mu      sync.Mutex
	records map[string]OperationRecord
}

func newOperationLedger() *operationLedger {
	return &operationLedger{records: make(map[string]OperationRecord)}
}

func (ledger *operationLedger) add(record OperationRecord) error {
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	if record.ID == "" {
		return errors.New("operation ID is required")
	}
	if record.Attempts != 1 {
		return fmt.Errorf("operation %s attempts=%d, want exactly 1", record.ID, record.Attempts)
	}
	if _, duplicate := ledger.records[record.ID]; duplicate {
		return fmt.Errorf("operation %s was recorded more than once", record.ID)
	}
	ledger.records[record.ID] = record
	return nil
}

func (ledger *operationLedger) snapshot() []OperationRecord {
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	records := make([]OperationRecord, 0, len(ledger.records))
	for _, record := range ledger.records {
		records = append(records, record)
	}
	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	return records
}

type DocumentSnapshot struct {
	Revision        int64  `json:"revision"`
	SHA256          string `json:"sha256"`
	Bytes           int64  `json:"bytes"`
	AuditRecords    int    `json:"audit_records"`
	ResourceRecords int    `json:"resource_records"`
}

type DatabaseCounters struct {
	XactCommit     int64 `json:"xact_commit"`
	XactRollback   int64 `json:"xact_rollback"`
	BlocksRead     int64 `json:"blocks_read"`
	BlocksHit      int64 `json:"blocks_hit"`
	TuplesReturned int64 `json:"tuples_returned"`
	TuplesFetched  int64 `json:"tuples_fetched"`
	TuplesInserted int64 `json:"tuples_inserted"`
	TuplesUpdated  int64 `json:"tuples_updated"`
	TuplesDeleted  int64 `json:"tuples_deleted"`
	Conflicts      int64 `json:"conflicts"`
	TempFiles      int64 `json:"temp_files"`
	TempBytes      int64 `json:"temp_bytes"`
	Deadlocks      int64 `json:"deadlocks"`
}

type WALCounters struct {
	Records        int64 `json:"records"`
	FullPageImages int64 `json:"full_page_images"`
	Bytes          int64 `json:"bytes"`
	BuffersFull    int64 `json:"buffers_full"`
}

type TableCounters struct {
	LiveTuples       int64 `json:"live_tuples"`
	DeadTuples       int64 `json:"dead_tuples"`
	VacuumCount      int64 `json:"vacuum_count"`
	AutovacuumCount  int64 `json:"autovacuum_count"`
	AnalyzeCount     int64 `json:"analyze_count"`
	AutoanalyzeCount int64 `json:"autoanalyze_count"`
}

type StorageSnapshot struct {
	Control          DocumentSnapshot `json:"control"`
	Identity         DocumentSnapshot `json:"identity"`
	ReceiptHeaders   int64            `json:"receipt_headers"`
	ReceiptDocuments int64            `json:"receipt_documents"`
	OperationClasses map[string]int64 `json:"operation_classes"`
	DatabaseBytes    int64            `json:"database_bytes"`
	Database         DatabaseCounters `json:"database"`
	WAL              WALCounters      `json:"wal"`
	DocumentTable    TableCounters    `json:"document_table"`
}

type StorageDelta struct {
	ControlRevision  int64            `json:"control_revision"`
	IdentityRevision int64            `json:"identity_revision"`
	ControlAudit     int              `json:"control_audit"`
	IdentityAudit    int              `json:"identity_audit"`
	ReceiptHeaders   int64            `json:"receipt_headers"`
	ReceiptDocuments int64            `json:"receipt_documents"`
	OperationClasses map[string]int64 `json:"operation_classes"`
	Database         DatabaseCounters `json:"database"`
	WAL              WALCounters      `json:"wal"`
}

type LockWaitSamples struct {
	Samples          int   `json:"samples"`
	SamplesWithWaits int   `json:"samples_with_waits"`
	MaximumWaiters   int64 `json:"maximum_waiters"`
	TransactionWaits int64 `json:"transaction_wait_observations"`
	TupleWaits       int64 `json:"tuple_wait_observations"`
}

type VacuumResult struct {
	DurationMicros int64         `json:"duration_micros"`
	Before         TableCounters `json:"before"`
	After          TableCounters `json:"after"`
}

type BudgetReport struct {
	WriteLatency               DurationSummary `json:"write_latency"`
	ReadLatency                DurationSummary `json:"read_latency"`
	LoadDurationMicros         int64           `json:"load_duration_micros"`
	LoadWritesPerSecond        float64         `json:"load_writes_per_second"`
	SoakDurationMicros         int64           `json:"soak_duration_micros"`
	MaximumWriteP95Micros      int64           `json:"maximum_write_p95_micros"`
	MaximumWriteP99Micros      int64           `json:"maximum_write_p99_micros"`
	MaximumWriteMicros         int64           `json:"maximum_write_micros"`
	MaximumReadP95Micros       int64           `json:"maximum_read_p95_micros"`
	MaximumReadP99Micros       int64           `json:"maximum_read_p99_micros"`
	MaximumReadMicros          int64           `json:"maximum_read_micros"`
	MinimumLoadWritesPerSecond float64         `json:"minimum_load_writes_per_second"`
	MinimumSoakMicros          int64           `json:"minimum_soak_micros"`
	MaximumSoakMicros          int64           `json:"maximum_soak_micros"`
	MaximumWALBytes            int64           `json:"maximum_wal_bytes"`
	MaximumAverageWALPerWrite  int64           `json:"maximum_average_wal_per_write"`
	MaximumWALBuffersFull      int64           `json:"maximum_wal_buffers_full"`
	MaximumDatabaseBytes       int64           `json:"maximum_database_bytes"`
	MaximumDocumentBytes       int64           `json:"maximum_document_bytes"`
	MaximumVacuumMicros        int64           `json:"maximum_vacuum_micros"`
	MaximumDeadTuples          int64           `json:"maximum_dead_tuples"`
}

type TerminalState struct {
	ControlRevision  int64             `json:"control_revision"`
	ControlSHA256    string            `json:"control_sha256"`
	ControlAudit     int               `json:"control_audit"`
	IdentityRevision int64             `json:"identity_revision"`
	IdentitySHA256   string            `json:"identity_sha256"`
	IdentityAudit    int               `json:"identity_audit"`
	ReceiptHeaders   int64             `json:"receipt_headers"`
	ReceiptDocuments int64             `json:"receipt_documents"`
	OperationClasses map[string]int64  `json:"operation_classes"`
	NodeStates       map[string]string `json:"node_states"`
	SessionRevoked   map[string]bool   `json:"session_revoked"`
}

type Report struct {
	Schema               string            `json:"schema"`
	Passed               bool              `json:"passed"`
	Error                string            `json:"error,omitempty"`
	PercentileDefinition string            `json:"percentile_definition"`
	ClientRetryPolicy    string            `json:"client_retry_policy"`
	Replicas             []string          `json:"replicas"`
	NetworkID            string            `json:"network_id"`
	StartedAt            time.Time         `json:"started_at"`
	CompletedAt          time.Time         `json:"completed_at"`
	Baseline             StorageSnapshot   `json:"baseline"`
	Terminal             StorageSnapshot   `json:"terminal"`
	Delta                StorageDelta      `json:"delta"`
	Budgets              BudgetReport      `json:"budgets"`
	LockWaits            LockWaitSamples   `json:"lock_waits"`
	Vacuum               VacuumResult      `json:"vacuum"`
	TerminalState        TerminalState     `json:"terminal_state"`
	Operations           []OperationRecord `json:"operations"`
}

func WriteJSONExclusive(path string, value any) error {
	if path == "" {
		return errors.New("output path is required")
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("encode output JSON: %w", err)
	}
	data = append(data, '\n')
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create private output: %w", err)
	}
	closeErr := error(nil)
	defer func() { _ = file.Close() }()
	if info, statErr := file.Stat(); statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return errors.New("private output metadata is invalid")
	}
	if _, err := file.Write(data); err != nil {
		return fmt.Errorf("write private output: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync private output: %w", err)
	}
	closeErr = file.Close()
	if closeErr != nil {
		return fmt.Errorf("close private output: %w", closeErr)
	}
	return nil
}

func ReadReport(path string) (Report, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Report{}, errors.New("read prior load report failed")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var report Report
	if err := decoder.Decode(&report); err != nil {
		return Report{}, errors.New("decode prior load report failed")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Report{}, errors.New("prior load report contains trailing data")
	}
	if report.Schema != ReportSchema || !report.Passed {
		return Report{}, errors.New("prior load report is not a successful supported report")
	}
	return report, nil
}
