package postgresloadgate

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"mesh/internal/control"
	"mesh/internal/postgresruntime"
)

type Config struct {
	Replicas             [2]string
	PublicOrigin         string
	NetworkID            string
	AdminTokenFile       string
	PostgresDSNFile      string
	GeneratedSecretsFile string
}

const (
	statsVisibilityApplicationPoolCapacity = 8
	statsVisibilityReservedConnections     = 1
	statsVisibilityProbesPerReplica        = statsVisibilityApplicationPoolCapacity - statsVisibilityReservedConnections
)

type statsVisibilityProbe struct {
	replica int
	ordinal int
}

func statsVisibilityProbePlan() []statsVisibilityProbe {
	probes := make([]statsVisibilityProbe, 0, 2*statsVisibilityProbesPerReplica)
	for replica := range 2 {
		for slot := range statsVisibilityProbesPerReplica {
			probes = append(probes, statsVisibilityProbe{replica: replica, ordinal: replica*statsVisibilityProbesPerReplica + slot})
		}
	}
	return probes
}

func validateConfig(config Config) error {
	if config.NetworkID == "" || len(config.NetworkID) > 128 || strings.ContainsAny(config.NetworkID, "/?#\r\n") {
		return errors.New("network ID is invalid")
	}
	for _, path := range []string{config.AdminTokenFile, config.PostgresDSNFile, config.GeneratedSecretsFile} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return errors.New("load-gate file paths must be clean and absolute")
		}
	}
	return nil
}

func statsVisibilityBarrier(ctx context.Context, client *httpWorkloadClient, poolRuntime *postgresruntime.Runtime, stage string) error {
	// PostgreSQL cumulative statistics are normally published just before a
	// backend goes idle, but no more often than once per second. Wait past that
	// interval, then drive seven distinct connections in each eight-connection
	// application pool while retaining one slot of defensive headroom. Global
	// writer concurrency is eight, writes alternate replicas and finish split
	// 128/128, so seven probes still cover every recently active per-replica
	// writer backend. Concurrent readiness checks coexist through the store's
	// shared migration advisory lock; only migration's exclusive form excludes
	// them. No writer is active at this boundary. The final force/clear calls make
	// this driver's PG17 backend publish and discard any cached snapshot before
	// the authoritative read.
	timer := time.NewTimer(1100 * time.Millisecond)
	select {
	case <-ctx.Done():
		timer.Stop()
		return ctx.Err()
	case <-timer.C:
	}
	probes := statsVisibilityProbePlan()
	tasks := make([]workloadTask, 0, len(probes))
	for _, probe := range probes {
		tasks = append(tasks, client.readTask(stage, "ready", probe.ordinal, probe.replica, ""))
	}
	if err := runConcurrent(ctx, tasks, len(tasks)); err != nil {
		return fmt.Errorf("PostgreSQL statistics visibility readiness barrier: %w", err)
	}
	timer = time.NewTimer(200 * time.Millisecond)
	select {
	case <-ctx.Done():
		timer.Stop()
		return ctx.Err()
	case <-timer.C:
	}
	pool := poolRuntime.Pool()
	if _, err := pool.Exec(ctx, `SELECT pg_catalog.pg_stat_force_next_flush()`); err != nil {
		return errors.New("force PostgreSQL statistics flush failed")
	}
	if _, err := pool.Exec(ctx, `SELECT pg_catalog.pg_stat_clear_snapshot()`); err != nil {
		return errors.New("clear PostgreSQL statistics snapshot failed")
	}
	return nil
}

func buildLoadTasks(client *httpWorkloadClient, networkID string, nodes []control.Node, sessions []string) (phaseOne, phaseTwo []workloadTask) {
	phaseOne = make([]workloadTask, 0, LoadNodeCreates+LoadSessionCreates)
	for index := range LoadNodeCreates {
		phaseOne = append(phaseOne, client.nodeCreateTask("load", index, index%2, networkID, nodes))
	}
	for index := range LoadSessionCreates {
		phaseOne = append(phaseOne, client.sessionCreateTask("load", index, (LoadNodeCreates+index)%2, sessions))
	}
	phaseTwo = make([]workloadTask, 0, LoadNodeReissues+LoadSessionRevokes)
	for index := range LoadNodeReissues {
		phaseTwo = append(phaseTwo, client.nodeReissueTask("load", index, index%2, nodes[index].ID))
	}
	for index := range LoadSessionRevokes {
		phaseTwo = append(phaseTwo, client.sessionRevokeTask("load", index, (LoadNodeReissues+index)%2, sessions[index]))
	}
	return phaseOne, phaseTwo
}

func buildSoakTasks(client *httpWorkloadClient, networkID string, nodes []control.Node, sessions []string) []workloadTask {
	tasks := make([]workloadTask, 0, ExpectedWrites-ExpectedLoadWrites+SoakReads)
	nodeIndex, sessionIndex, globalRead := 0, 0, 0
	readOrdinals := map[string]int{"ready": 0, "networks": 0, "nodes": 0, "sessions": 0}
	readKinds := []string{"ready", "networks", "nodes", "sessions"}
	for cycle := range 36 {
		writeReplica := soakWriteReplica(cycle)
		if cycle%3 == 2 {
			sessionOrdinal := LoadSessionRevokes + sessionIndex
			tasks = append(tasks, client.sessionRevokeTask("soak", sessionOrdinal, writeReplica, sessions[sessionOrdinal]))
			sessionIndex++
		} else {
			tasks = append(tasks, client.nodeRevokeTask("soak", nodeIndex, writeReplica, nodes[nodeIndex].ID))
			nodeIndex++
		}
		for range 3 {
			kind := readKinds[globalRead%len(readKinds)]
			ordinal := readOrdinals[kind]
			readOrdinals[kind]++
			replica := (cycle*4 + 1 + globalRead%3) % 2
			tasks = append(tasks, client.readTask("soak", kind, ordinal, replica, networkID))
			globalRead++
		}
	}
	return tasks
}

func soakWriteReplica(cycle int) int { return cycle % 2 }

func auditActionCounts(events []control.AuditEvent) map[string]int {
	counts := make(map[string]int)
	for _, event := range events {
		counts[event.Action]++
	}
	return counts
}

func identityAuditTypeCounts(document identityDocument) map[string]int {
	counts := make(map[string]int)
	for _, event := range document.Audit {
		counts[string(event.Type)]++
	}
	return counts
}

func subtractIntMaps(after, before map[string]int) map[string]int {
	result := make(map[string]int)
	for key, value := range after {
		result[key] = value - before[key]
	}
	for key, value := range before {
		if _, found := after[key]; !found {
			result[key] = -value
		}
	}
	return result
}

func validateTerminalDocuments(baseline, terminal loadedDocuments, nodes []control.Node, sessions []string, snapshot StorageSnapshot) (TerminalState, error) {
	if len(terminal.control.Nodes)-len(baseline.control.Nodes) != LoadNodeCreates {
		return TerminalState{}, fmt.Errorf("terminal control node delta=%d, want %d", len(terminal.control.Nodes)-len(baseline.control.Nodes), LoadNodeCreates)
	}
	if len(terminal.identity.Sessions)-len(baseline.identity.Sessions) != LoadSessionCreates {
		return TerminalState{}, fmt.Errorf("terminal identity session delta=%d, want %d", len(terminal.identity.Sessions)-len(baseline.identity.Sessions), LoadSessionCreates)
	}
	baselineNodes := make(map[string]struct{}, len(baseline.control.Nodes))
	for _, node := range baseline.control.Nodes {
		baselineNodes[node.ID] = struct{}{}
	}
	terminalNodes := make(map[string]persistedNode, len(terminal.control.Nodes))
	for _, node := range terminal.control.Nodes {
		if _, duplicate := terminalNodes[node.ID]; duplicate {
			return TerminalState{}, errors.New("terminal control document repeats a node ID")
		}
		terminalNodes[node.ID] = node
	}
	nodeStates := make(map[string]string, len(nodes))
	for index, expected := range nodes {
		if expected.ID == "" {
			return TerminalState{}, errors.New("workload node result is incomplete")
		}
		if _, existed := baselineNodes[expected.ID]; existed {
			return TerminalState{}, errors.New("workload node ID collided with baseline")
		}
		actual, found := terminalNodes[expected.ID]
		if !found || actual.Name != fmt.Sprintf("load-node-%03d", index+1) {
			return TerminalState{}, errors.New("terminal control document omitted or renamed a workload node")
		}
		wantStatus := "pending"
		if index < SoakNodeRevokes {
			wantStatus = "revoked"
			if actual.RevokedAt == nil {
				return TerminalState{}, errors.New("revoked workload node lacks a revocation timestamp")
			}
		} else if actual.RevokedAt != nil {
			return TerminalState{}, errors.New("pending workload node has a revocation timestamp")
		}
		if actual.Status != wantStatus {
			return TerminalState{}, fmt.Errorf("workload node %s status=%q, want %q", actual.ID, actual.Status, wantStatus)
		}
		nodeStates[actual.ID] = actual.Status
	}
	baselineSessions := make(map[string]struct{}, len(baseline.identity.Sessions))
	for _, session := range baseline.identity.Sessions {
		baselineSessions[session.ID] = struct{}{}
	}
	terminalSessions := make(map[string]bool, len(terminal.identity.Sessions))
	for _, session := range terminal.identity.Sessions {
		if _, duplicate := terminalSessions[session.ID]; duplicate {
			return TerminalState{}, errors.New("terminal identity document repeats a session ID")
		}
		terminalSessions[session.ID] = session.RevokedAt != nil
	}
	sessionRevoked := make(map[string]bool, len(sessions))
	for _, id := range sessions {
		if id == "" {
			return TerminalState{}, errors.New("workload session result is incomplete")
		}
		if _, existed := baselineSessions[id]; existed {
			return TerminalState{}, errors.New("workload session ID collided with baseline")
		}
		revoked, found := terminalSessions[id]
		if !found || !revoked {
			return TerminalState{}, fmt.Errorf("workload session %s is missing or not revoked", id)
		}
		sessionRevoked[id] = true
	}
	controlActions := subtractIntMaps(auditActionCounts(terminal.control.Audit), auditActionCounts(baseline.control.Audit))
	if controlActions["node.created"] != LoadNodeCreates || controlActions["node.enrollment_reissued"] != LoadNodeReissues || controlActions["node.revoked"] != SoakNodeRevokes {
		return TerminalState{}, fmt.Errorf("terminal control audit action deltas are not exact: %#v", controlActions)
	}
	for action, count := range controlActions {
		if action != "node.created" && action != "node.enrollment_reissued" && action != "node.revoked" && count != 0 {
			return TerminalState{}, fmt.Errorf("unexpected control audit action delta %q=%d", action, count)
		}
	}
	identityActions := subtractIntMaps(identityAuditTypeCounts(terminal.identity), identityAuditTypeCounts(baseline.identity))
	if identityActions["session.created"] != LoadSessionCreates || identityActions["session.revoked"] != LoadSessionCreates {
		return TerminalState{}, fmt.Errorf("terminal identity audit action deltas are not exact: %#v", identityActions)
	}
	for action, count := range identityActions {
		if action != "session.created" && action != "session.revoked" && count != 0 {
			return TerminalState{}, fmt.Errorf("unexpected identity audit action delta %q=%d", action, count)
		}
	}
	return TerminalState{
		ControlRevision: snapshot.Control.Revision, ControlSHA256: snapshot.Control.SHA256, ControlAudit: snapshot.Control.AuditRecords,
		IdentityRevision: snapshot.Identity.Revision, IdentitySHA256: snapshot.Identity.SHA256, IdentityAudit: snapshot.Identity.AuditRecords,
		ReceiptHeaders: snapshot.ReceiptHeaders, ReceiptDocuments: snapshot.ReceiptDocuments,
		OperationClasses: cloneInt64Map(snapshot.OperationClasses), NodeStates: nodeStates, SessionRevoked: sessionRevoked,
	}, nil
}

func cloneInt64Map(value map[string]int64) map[string]int64 {
	result := make(map[string]int64, len(value))
	for key, item := range value {
		result[key] = item
	}
	return result
}

func budgetReport(writes, reads DurationSummary, loadDuration, soakDuration time.Duration) BudgetReport {
	return BudgetReport{
		WriteLatency: writes, ReadLatency: reads,
		LoadDurationMicros: loadDuration.Microseconds(), LoadWritesPerSecond: float64(ExpectedLoadWrites) / loadDuration.Seconds(),
		SoakDurationMicros:    soakDuration.Microseconds(),
		MaximumWriteP95Micros: MaximumWriteP95.Microseconds(), MaximumWriteP99Micros: MaximumWriteP99.Microseconds(), MaximumWriteMicros: MaximumWrite.Microseconds(),
		MaximumReadP95Micros: MaximumReadP95.Microseconds(), MaximumReadP99Micros: MaximumReadP99.Microseconds(), MaximumReadMicros: MaximumRead.Microseconds(),
		MinimumLoadWritesPerSecond: MinimumLoadWritesPerSecond, MinimumSoakMicros: MinimumSoakDuration.Microseconds(), MaximumSoakMicros: MaximumSoakDuration.Microseconds(),
		MaximumWALBytes: MaximumWALBytes, MaximumAverageWALPerWrite: MaximumAverageWALPerWrite, MaximumWALBuffersFull: MaximumWALBuffersFull,
		MaximumDatabaseBytes: MaximumDatabaseBytes, MaximumDocumentBytes: MaximumDocumentBytes,
		MaximumVacuumMicros: MaximumVacuumDuration.Microseconds(), MaximumDeadTuples: MaximumDeadTuplesAfterVacuum,
	}
}

func Run(ctx context.Context, config Config) (report Report, runErr error) {
	report = Report{
		Schema:               ReportSchema,
		PercentileDefinition: "nearest-rank: ascending observation at one-based rank ceil(percentile/100*N), without interpolation",
		ClientRetryPolicy:    "one http.Client.Do call per logical operation; no application retry; mutation bodies are not replayable; fresh connections disable reused-connection retry",
		Replicas:             append([]string(nil), config.Replicas[:]...), NetworkID: config.NetworkID, StartedAt: time.Now().UTC(),
	}
	ledger := newOperationLedger()
	defer func() {
		report.CompletedAt = time.Now().UTC()
		report.Operations = ledger.snapshot()
		if runErr != nil {
			report.Passed = false
			report.Error = runErr.Error()
		}
	}()
	if ctx == nil {
		return report, errors.New("load-gate context is required")
	}
	if err := validateConfig(config); err != nil {
		return report, err
	}
	adminToken, err := readPrivateCanonicalLine(config.AdminTokenFile, "administrator token")
	if err != nil {
		return report, err
	}
	if !control.ValidBearerToken(adminToken) {
		return report, errors.New("administrator token is not a canonical bearer")
	}
	secrets, err := newSecretSink(config.GeneratedSecretsFile)
	if err != nil {
		return report, err
	}
	defer func() { runErr = errors.Join(runErr, secrets.close()) }()
	postgres, err := postgresruntime.Open(ctx, postgresruntime.Options{DSNFile: config.PostgresDSNFile, AllowLocalPlaintext: true})
	if err != nil {
		return report, err
	}
	defer func() { runErr = errors.Join(runErr, postgres.Close()) }()
	client, err := newHTTPWorkloadClient(config.Replicas, config.PublicOrigin, adminToken, ledger, secrets)
	if err != nil {
		return report, err
	}
	defer client.close()
	adminToken = ""

	warmOne, err := client.validationInventory(ctx, "warm", 0, config.NetworkID)
	if err != nil {
		return report, err
	}
	warmTwo, err := client.validationInventory(ctx, "warm", 1, config.NetworkID)
	if err != nil {
		return report, err
	}
	if err := assertReplicaInventories(warmOne, warmTwo); err != nil {
		return report, err
	}
	if err := statsVisibilityBarrier(ctx, client, postgres, "baseline-stats-sync"); err != nil {
		return report, err
	}
	baseline, baselineDocuments, err := readStorageSnapshot(ctx, postgres.Pool())
	if err != nil {
		return report, err
	}
	if err := validateReceiptIntegrity(ctx, postgres.Pool(), baseline); err != nil {
		return report, err
	}
	report.Baseline = baseline

	sampler := startLockWaitSampler(ctx, postgres.Pool())
	samplerStopped := false
	defer func() {
		if !samplerStopped {
			_, _ = sampler.stop()
		}
	}()
	nodes := make([]control.Node, LoadNodeCreates)
	sessions := make([]string, LoadSessionCreates)
	phaseOne, _ := buildLoadTasks(client, config.NetworkID, nodes, sessions)
	loadStarted := time.Now()
	if err := runConcurrent(ctx, phaseOne, WorkerConcurrency); err != nil {
		return report, fmt.Errorf("load dependency phase one failed: %w", err)
	}
	_, phaseTwo := buildLoadTasks(client, config.NetworkID, nodes, sessions)
	if err := runConcurrent(ctx, phaseTwo, WorkerConcurrency); err != nil {
		return report, fmt.Errorf("load dependency phase two failed: %w", err)
	}
	loadDuration := time.Since(loadStarted)

	soakTasks := buildSoakTasks(client, config.NetworkID, nodes, sessions)
	soakDuration, err := pacedSoak(ctx, soakTasks, SoakDuration)
	if err != nil {
		return report, fmt.Errorf("paced mixed micro-soak failed: %w", err)
	}
	terminalOne, err := client.validationInventory(ctx, "terminal-validation", 0, config.NetworkID)
	if err != nil {
		return report, err
	}
	terminalTwo, err := client.validationInventory(ctx, "terminal-validation", 1, config.NetworkID)
	if err != nil {
		return report, err
	}
	if err := assertReplicaInventories(terminalOne, terminalTwo); err != nil {
		return report, err
	}
	if err := statsVisibilityBarrier(ctx, client, postgres, "terminal-stats-sync"); err != nil {
		return report, err
	}
	lockWaits, err := sampler.stop()
	samplerStopped = true
	if err != nil {
		return report, err
	}
	report.LockWaits = lockWaits
	terminal, terminalDocuments, err := readStorageSnapshot(ctx, postgres.Pool())
	if err != nil {
		return report, err
	}
	report.Terminal = terminal
	report.Delta = storageDelta(terminal, baseline)
	if err := validateStorageDelta(report.Delta, terminal); err != nil {
		return report, err
	}
	if err := validateReceiptIntegrity(ctx, postgres.Pool(), terminal); err != nil {
		return report, err
	}
	terminalState, err := validateTerminalDocuments(baselineDocuments, terminalDocuments, nodes, sessions, terminal)
	if err != nil {
		return report, err
	}
	if err := assertAPIInventory(terminalOne, terminalState); err != nil {
		return report, err
	}
	report.TerminalState = terminalState

	records := ledger.snapshot()
	writeDurations, readDurations, successfulLoadWrites, err := operationDurations(records)
	if err != nil {
		return report, err
	}
	writes, err := SummarizeDurations(writeDurations)
	if err != nil {
		return report, err
	}
	reads, err := SummarizeDurations(readDurations)
	if err != nil {
		return report, err
	}
	if err := ValidateLatencyBudget(LatencyBudgetInput{
		Writes: writes, Reads: reads, LoadDuration: loadDuration, SoakDuration: soakDuration, SuccessfulLoadWrites: successfulLoadWrites,
	}); err != nil {
		return report, err
	}
	report.Budgets = budgetReport(writes, reads, loadDuration, soakDuration)
	vacuum, err := runVacuum(ctx, postgres.Pool())
	report.Vacuum = vacuum
	if err != nil {
		return report, err
	}
	report.Passed = true
	return report, nil
}

type RestartVerification struct {
	Schema        string            `json:"schema"`
	Passed        bool              `json:"passed"`
	Error         string            `json:"error,omitempty"`
	VerifiedAt    time.Time         `json:"verified_at"`
	Replicas      []string          `json:"replicas"`
	NetworkID     string            `json:"network_id"`
	TerminalState TerminalState     `json:"terminal_state"`
	Operations    []OperationRecord `json:"operations"`
}

func VerifyRestart(ctx context.Context, config Config, expected Report) (verification RestartVerification, verifyErr error) {
	verification = RestartVerification{Schema: ReportSchema + "-restart-verification", Replicas: append([]string(nil), config.Replicas[:]...), NetworkID: config.NetworkID}
	if expected.Schema != ReportSchema || !expected.Passed {
		return verification, errors.New("successful expected report is required")
	}
	if !reflect.DeepEqual(expected.Replicas, config.Replicas[:]) || expected.NetworkID != config.NetworkID {
		return verification, errors.New("restart verification target does not match load report")
	}
	if err := validateConfig(config); err != nil {
		return verification, err
	}
	adminToken, err := readPrivateCanonicalLine(config.AdminTokenFile, "administrator token")
	if err != nil {
		return verification, err
	}
	postgres, err := postgresruntime.Open(ctx, postgresruntime.Options{DSNFile: config.PostgresDSNFile, AllowLocalPlaintext: true})
	if err != nil {
		return verification, err
	}
	defer func() { verifyErr = errors.Join(verifyErr, postgres.Close()) }()
	ledger := newOperationLedger()
	// Verification produces no new credentials. A closed placeholder sink is
	// sufficient because every verification operation is read-only.
	client, err := newHTTPWorkloadClient(config.Replicas, config.PublicOrigin, adminToken, ledger, &secretSink{closed: true})
	if err != nil {
		return verification, err
	}
	defer client.close()
	adminToken = ""
	one, err := client.validationInventory(ctx, "restart-validation", 0, config.NetworkID)
	if err != nil {
		return verification, err
	}
	two, err := client.validationInventory(ctx, "restart-validation", 1, config.NetworkID)
	if err != nil {
		return verification, err
	}
	if err := assertReplicaInventories(one, two); err != nil {
		return verification, err
	}
	if err := assertAPIInventory(one, expected.TerminalState); err != nil {
		return verification, err
	}
	snapshot, _, err := readStorageSnapshot(ctx, postgres.Pool())
	if err != nil {
		return verification, err
	}
	if err := validateReceiptIntegrity(ctx, postgres.Pool(), snapshot); err != nil {
		return verification, err
	}
	actualState := TerminalState{
		ControlRevision: snapshot.Control.Revision, ControlSHA256: snapshot.Control.SHA256, ControlAudit: snapshot.Control.AuditRecords,
		IdentityRevision: snapshot.Identity.Revision, IdentitySHA256: snapshot.Identity.SHA256, IdentityAudit: snapshot.Identity.AuditRecords,
		ReceiptHeaders: snapshot.ReceiptHeaders, ReceiptDocuments: snapshot.ReceiptDocuments,
		OperationClasses: cloneInt64Map(snapshot.OperationClasses), NodeStates: expected.TerminalState.NodeStates, SessionRevoked: expected.TerminalState.SessionRevoked,
	}
	if !reflect.DeepEqual(actualState, expected.TerminalState) {
		return verification, fmt.Errorf("restart changed exact terminal state: got %+v want %+v", actualState, expected.TerminalState)
	}
	verification.Passed = true
	verification.VerifiedAt = time.Now().UTC()
	verification.TerminalState = actualState
	verification.Operations = ledger.snapshot()
	return verification, nil
}

func VerifyReportOperations(report Report) error {
	seen := make(map[string]struct{}, len(report.Operations))
	for _, record := range report.Operations {
		if record.ID == "" || record.Attempts != 1 {
			return errors.New("report contains an invalid logical operation attempt count")
		}
		if _, duplicate := seen[record.ID]; duplicate {
			return errors.New("report contains a duplicate logical operation ID")
		}
		seen[record.ID] = struct{}{}
	}
	ids := make([]string, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	if len(ids) == 0 {
		return errors.New("report contains no logical operations")
	}
	return nil
}
