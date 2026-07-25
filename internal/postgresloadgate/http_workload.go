package postgresloadgate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"mesh/internal/control"
	"mesh/internal/identity"
)

const maximumResponseBytes = 2 << 20

type namedSecret struct {
	kind  string
	value string
}

type secretSink struct {
	mu     sync.Mutex
	file   *os.File
	closed bool
}

func newSecretSink(path string) (*secretSink, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("generated-secret output path must be clean and absolute")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, errors.New("create generated-secret output failed")
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		file.Close()
		return nil, errors.New("generated-secret output metadata is invalid")
	}
	return &secretSink{file: file}, nil
}

func (sink *secretSink) add(secrets ...namedSecret) error {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if sink == nil || sink.file == nil || sink.closed {
		return errors.New("generated-secret output is closed")
	}
	for _, secret := range secrets {
		if secret.kind == "" || strings.ContainsAny(secret.kind, "\t\r\n") || secret.value == "" || strings.ContainsAny(secret.value, "\t\r\n") {
			return errors.New("generated secret record is invalid")
		}
		if _, err := fmt.Fprintf(sink.file, "%s\t%s\n", secret.kind, secret.value); err != nil {
			return errors.New("write generated-secret output failed")
		}
	}
	return nil
}

func (sink *secretSink) close() error {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if sink == nil || sink.file == nil || sink.closed {
		return nil
	}
	sink.closed = true
	if err := sink.file.Sync(); err != nil {
		_ = sink.file.Close()
		return errors.New("sync generated-secret output failed")
	}
	if err := sink.file.Close(); err != nil {
		return errors.New("close generated-secret output failed")
	}
	return nil
}

type requestSpec struct {
	id             string
	stage          string
	kind           string
	replica        int
	method         string
	path           string
	body           []byte
	write          bool
	expectedStatus int
	auth           bool
	origin         bool
}

type responseResult struct {
	record  OperationRecord
	body    []byte
	cookies []*http.Cookie
}

type httpWorkloadClient struct {
	replicas [2]string
	origin   string
	token    string
	client   *http.Client
	ledger   *operationLedger
	secrets  *secretSink
}

func newHTTPWorkloadClient(replicas [2]string, origin, token string, ledger *operationLedger, secrets *secretSink) (*httpWorkloadClient, error) {
	if !control.ValidBearerToken(token) {
		return nil, errors.New("administrator token is not canonical")
	}
	for _, raw := range append(replicas[:], origin) {
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Scheme != "http" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" {
			return nil, errors.New("workload URLs must be bare HTTP origins")
		}
		host, _, err := net.SplitHostPort(parsed.Host)
		if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
			return nil, errors.New("workload URLs must use numeric loopback hosts")
		}
	}
	if replicas[0] == replicas[1] {
		return nil, errors.New("two distinct replica URLs are required")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	// Every request gets a fresh connection and mutation bodies deliberately
	// have no GetBody function. The standard transport therefore has neither a
	// reused connection nor a replayable body on which to perform an implicit
	// retry. Each logical operation calls Do exactly once.
	transport.DisableKeepAlives = true
	transport.Proxy = nil
	transport.MaxConnsPerHost = WorkerConcurrency
	transport.ResponseHeaderTimeout = MaximumWrite + 2*time.Second
	return &httpWorkloadClient{
		replicas: replicas, origin: origin, token: token, ledger: ledger, secrets: secrets,
		client: &http.Client{
			Transport: transport,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return errors.New("redirects are forbidden for load-gate operations")
			},
		},
	}, nil
}

func (client *httpWorkloadClient) close() {
	if client == nil || client.client == nil {
		return
	}
	if transport, ok := client.client.Transport.(*http.Transport); ok {
		transport.CloseIdleConnections()
	}
	client.token = ""
}

func (client *httpWorkloadClient) perform(ctx context.Context, spec requestSpec) (responseResult, error) {
	record := OperationRecord{
		ID: spec.id, Stage: spec.stage, Kind: spec.kind, Replica: spec.replica + 1,
		Method: spec.method, Path: spec.path, Write: spec.write, Attempts: 1,
		ExpectedStatus: spec.expectedStatus, StartedAt: time.Now().UTC(),
	}
	if spec.replica < 0 || spec.replica >= len(client.replicas) {
		record.Error = "invalid replica selector"
		_ = client.ledger.add(record)
		return responseResult{record: record}, errors.New(record.Error)
	}
	timeout := MaximumRead + 2*time.Second
	if spec.write {
		timeout = MaximumWrite + 2*time.Second
	}
	requestCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var body io.Reader
	if spec.body != nil {
		// NopCloser prevents http.NewRequestWithContext from synthesizing a
		// replay body for mutations.
		body = io.NopCloser(bytes.NewReader(spec.body))
	}
	request, err := http.NewRequestWithContext(requestCtx, spec.method, client.replicas[spec.replica]+spec.path, body)
	if err != nil {
		record.Error = "construct request failed"
		_ = client.ledger.add(record)
		return responseResult{record: record}, errors.New(record.Error)
	}
	request.Header.Set("Accept", "application/json")
	if spec.body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if spec.auth {
		request.Header.Set("Authorization", "Bearer "+client.token)
	}
	if spec.origin {
		request.Header.Set("Origin", client.origin)
		request.Header.Set("Sec-Fetch-Site", "same-origin")
	}
	started := time.Now()
	response, err := client.client.Do(request)
	record.DurationMicros = time.Since(started).Microseconds()
	if err != nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		record.Error = "HTTP transport failed without retry"
		digest := sha256.Sum256(nil)
		record.ResponseSHA256 = hex.EncodeToString(digest[:])
		if addErr := client.ledger.add(record); addErr != nil {
			return responseResult{record: record}, addErr
		}
		return responseResult{record: record}, fmt.Errorf("operation %s: %s", spec.id, record.Error)
	}
	raw, readErr := io.ReadAll(io.LimitReader(response.Body, maximumResponseBytes+1))
	closeErr := response.Body.Close()
	record.Status = response.StatusCode
	record.ResponseBytes = len(raw)
	digest := sha256.Sum256(raw)
	record.ResponseSHA256 = hex.EncodeToString(digest[:])
	result := responseResult{record: record, body: raw, cookies: response.Cookies()}
	if readErr != nil || closeErr != nil || len(raw) > maximumResponseBytes {
		record.Error = "bounded HTTP response read failed"
		result.record = record
		if addErr := client.ledger.add(record); addErr != nil {
			return result, addErr
		}
		return result, fmt.Errorf("operation %s: %s", spec.id, record.Error)
	}
	if response.StatusCode != spec.expectedStatus {
		record.Error = "unexpected HTTP status"
		result.record = record
		if addErr := client.ledger.add(record); addErr != nil {
			return result, addErr
		}
		return result, fmt.Errorf("operation %s returned HTTP %d, want %d (response sha256 %s)", spec.id, response.StatusCode, spec.expectedStatus, record.ResponseSHA256)
	}
	result.record = record
	return result, nil
}

func (client *httpWorkloadClient) finish(result responseResult, resourceID string, secrets []namedSecret, operationErr error) error {
	record := result.record
	record.ResourceID = resourceID
	if operationErr != nil {
		record.Error = operationErr.Error()
	}
	if len(secrets) > 0 {
		if err := client.secrets.add(secrets...); err != nil && operationErr == nil {
			operationErr = err
			record.Error = err.Error()
		}
	}
	if err := client.ledger.add(record); err != nil {
		return err
	}
	if operationErr != nil {
		return fmt.Errorf("operation %s: %w", record.ID, operationErr)
	}
	return nil
}

type workloadTask func(context.Context) error

func runConcurrent(ctx context.Context, tasks []workloadTask, concurrency int) error {
	if concurrency < 1 {
		return errors.New("workload concurrency must be positive")
	}
	jobs := make(chan workloadTask)
	errorsByTask := make(chan error, len(tasks))
	var workers sync.WaitGroup
	for range concurrency {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for task := range jobs {
				errorsByTask <- task(ctx)
			}
		}()
	}
	for _, task := range tasks {
		jobs <- task
	}
	close(jobs)
	workers.Wait()
	close(errorsByTask)
	var combined error
	for err := range errorsByTask {
		if err != nil {
			combined = errors.Join(combined, err)
		}
	}
	return combined
}

func decodeResponse(raw []byte, target any) error {
	if err := decodeOneStrict(raw, target); err != nil {
		return errors.New("strict response JSON decode failed")
	}
	return nil
}

func validateReadyResponse(raw []byte) error {
	var response struct {
		Status string `json:"status"`
	}
	if err := decodeResponse(raw, &response); err != nil {
		return err
	}
	if response.Status != "ready" {
		return errors.New("readiness response contract is invalid")
	}
	return nil
}

func (client *httpWorkloadClient) nodeCreateTask(stage string, index, replica int, networkID string, nodes []control.Node) workloadTask {
	return func(ctx context.Context) error {
		body, _ := json.Marshal(control.CreateNodeInput{Name: fmt.Sprintf("load-node-%03d", index+1), Role: "member"})
		spec := requestSpec{
			id: fmt.Sprintf("%s.control.node-create.%03d", stage, index+1), stage: stage, kind: "node_create", replica: replica,
			method: http.MethodPost, path: "/api/v1/networks/" + url.PathEscape(networkID) + "/nodes", body: body,
			write: true, expectedStatus: http.StatusCreated, auth: true,
		}
		result, err := client.perform(ctx, spec)
		if err != nil {
			return err
		}
		var created control.CreatedNode
		parseErr := decodeResponse(result.body, &created)
		if parseErr == nil && (!control.ValidBearerToken(created.EnrollmentToken) || created.Node.ID == "" || created.Node.Name != fmt.Sprintf("load-node-%03d", index+1) || created.Node.Status != "pending") {
			parseErr = errors.New("node-create response contract is invalid")
		}
		if parseErr == nil {
			nodes[index] = created.Node
		}
		secrets := []namedSecret(nil)
		if control.ValidBearerToken(created.EnrollmentToken) {
			secrets = append(secrets, namedSecret{kind: "enrollment", value: created.EnrollmentToken})
		}
		return client.finish(result, created.Node.ID, secrets, parseErr)
	}
}

func (client *httpWorkloadClient) sessionCreateTask(stage string, index, replica int, sessions []string) workloadTask {
	return func(ctx context.Context) error {
		body, _ := json.Marshal(map[string]string{"token": client.token})
		spec := requestSpec{
			id: fmt.Sprintf("%s.identity.session-create.%03d", stage, index+1), stage: stage, kind: "session_create", replica: replica,
			method: http.MethodPost, path: "/api/v1/session", body: body, write: true, expectedStatus: http.StatusOK, origin: true,
		}
		result, err := client.perform(ctx, spec)
		if err != nil {
			return err
		}
		var response struct {
			Authenticated     bool               `json:"authenticated"`
			SessionID         string             `json:"session_id"`
			Principal         identity.Principal `json:"principal"`
			AuthMethod        string             `json:"auth_method"`
			CreatedAt         *time.Time         `json:"created_at"`
			LastSeenAt        *time.Time         `json:"last_seen_at"`
			IdleExpiresAt     *time.Time         `json:"idle_expires_at"`
			AbsoluteExpiresAt *time.Time         `json:"absolute_expires_at"`
		}
		parseErr := decodeResponse(result.body, &response)
		if parseErr == nil && (!response.Authenticated || response.SessionID == "" || response.AuthMethod != "legacy_token") {
			parseErr = errors.New("session-create response contract is invalid")
		}
		cookieValues := make(map[string]string)
		for _, cookie := range result.cookies {
			if cookie.Name == "mesh_session" || cookie.Name == "mesh_csrf" {
				if _, duplicate := cookieValues[cookie.Name]; duplicate {
					parseErr = errors.New("session response repeated a credential cookie")
					continue
				}
				cookieValues[cookie.Name] = cookie.Value
			}
		}
		if parseErr == nil && (!control.ValidBearerToken(cookieValues["mesh_session"]) || !control.ValidBearerToken(cookieValues["mesh_csrf"]) || cookieValues["mesh_session"] == cookieValues["mesh_csrf"]) {
			parseErr = errors.New("session response credential cookies are invalid")
		}
		if parseErr == nil {
			sessions[index] = response.SessionID
		}
		secrets := []namedSecret{}
		if control.ValidBearerToken(cookieValues["mesh_session"]) {
			secrets = append(secrets, namedSecret{kind: "session_cookie", value: cookieValues["mesh_session"]})
		}
		if control.ValidBearerToken(cookieValues["mesh_csrf"]) {
			secrets = append(secrets, namedSecret{kind: "csrf_cookie", value: cookieValues["mesh_csrf"]})
		}
		return client.finish(result, response.SessionID, secrets, parseErr)
	}
}

func (client *httpWorkloadClient) nodeReissueTask(stage string, index, replica int, nodeID string) workloadTask {
	return func(ctx context.Context) error {
		spec := requestSpec{
			id: fmt.Sprintf("%s.control.enrollment-reissue.%03d", stage, index+1), stage: stage, kind: "enrollment_reissue", replica: replica,
			method: http.MethodPost, path: "/api/v1/nodes/" + url.PathEscape(nodeID) + "/enrollment/reissue", body: []byte(`{}`),
			write: true, expectedStatus: http.StatusOK, auth: true,
		}
		result, err := client.perform(ctx, spec)
		if err != nil {
			return err
		}
		var issued control.ReissuedEnrollment
		parseErr := decodeResponse(result.body, &issued)
		if parseErr == nil && (issued.Node.ID != nodeID || !control.ValidBearerToken(issued.EnrollmentToken)) {
			parseErr = errors.New("enrollment-reissue response contract is invalid")
		}
		secrets := []namedSecret(nil)
		if control.ValidBearerToken(issued.EnrollmentToken) {
			secrets = append(secrets, namedSecret{kind: "reissue_enrollment", value: issued.EnrollmentToken})
		}
		return client.finish(result, issued.Node.ID, secrets, parseErr)
	}
}

func (client *httpWorkloadClient) nodeRevokeTask(stage string, index, replica int, nodeID string) workloadTask {
	return func(ctx context.Context) error {
		spec := requestSpec{
			id: fmt.Sprintf("%s.control.node-revoke.%03d", stage, index+1), stage: stage, kind: "node_revoke", replica: replica,
			method: http.MethodPost, path: "/api/v1/nodes/" + url.PathEscape(nodeID) + "/revoke", body: []byte(`{}`),
			write: true, expectedStatus: http.StatusOK, auth: true,
		}
		result, err := client.perform(ctx, spec)
		if err != nil {
			return err
		}
		var node control.Node
		parseErr := decodeResponse(result.body, &node)
		if parseErr == nil && (node.ID != nodeID || node.Status != "revoked" || node.RevokedAt == nil) {
			parseErr = errors.New("node-revoke response contract is invalid")
		}
		return client.finish(result, node.ID, nil, parseErr)
	}
}

func (client *httpWorkloadClient) sessionRevokeTask(stage string, ordinal, replica int, sessionID string) workloadTask {
	return func(ctx context.Context) error {
		spec := requestSpec{
			id: fmt.Sprintf("%s.identity.session-revoke.%03d", stage, ordinal+1), stage: stage, kind: "session_revoke", replica: replica,
			method: http.MethodDelete, path: "/api/v1/sessions/" + url.PathEscape(sessionID),
			write: true, expectedStatus: http.StatusNoContent, auth: true,
		}
		result, err := client.perform(ctx, spec)
		if err != nil {
			return err
		}
		parseErr := error(nil)
		if len(result.body) != 0 {
			parseErr = errors.New("session-revoke response body is not empty")
		}
		return client.finish(result, sessionID, nil, parseErr)
	}
}

func readOperationID(stage, kind string, ordinal int) string {
	return fmt.Sprintf("%s.read.%s.%03d", stage, kind, ordinal+1)
}

func (client *httpWorkloadClient) readTask(stage, kind string, ordinal, replica int, networkID string) workloadTask {
	return func(ctx context.Context) error {
		path := "/readyz"
		auth := false
		switch kind {
		case "ready":
		case "networks":
			path, auth = "/api/v1/networks", true
		case "nodes":
			path, auth = "/api/v1/networks/"+url.PathEscape(networkID)+"/nodes", true
		case "sessions":
			path, auth = "/api/v1/sessions?include_revoked=true&limit=256", true
		default:
			return errors.New("unsupported read operation")
		}
		spec := requestSpec{
			id: readOperationID(stage, kind, ordinal), stage: stage, kind: kind, replica: replica,
			method: http.MethodGet, path: path, expectedStatus: http.StatusOK, auth: auth,
		}
		result, err := client.perform(ctx, spec)
		if err != nil {
			return err
		}
		parseErr := error(nil)
		switch kind {
		case "ready":
			parseErr = validateReadyResponse(result.body)
		case "networks":
			var items []control.NetworkSummary
			parseErr = decodeResponse(result.body, &items)
		case "nodes":
			var items []control.Node
			parseErr = decodeResponse(result.body, &items)
		case "sessions":
			var items []identity.SessionSummary
			parseErr = decodeResponse(result.body, &items)
		}
		return client.finish(result, "", nil, parseErr)
	}
}

type apiInventory struct {
	nodes    []control.Node
	sessions []identity.SessionSummary
}

func (client *httpWorkloadClient) validationInventory(ctx context.Context, stage string, replica int, networkID string) (apiInventory, error) {
	readyResult, err := client.perform(ctx, requestSpec{
		id: fmt.Sprintf("%s.replica-%d.ready", stage, replica+1), stage: stage, kind: "ready", replica: replica,
		method: http.MethodGet, path: "/readyz", expectedStatus: http.StatusOK,
	})
	if err != nil {
		return apiInventory{}, err
	}
	readyErr := validateReadyResponse(readyResult.body)
	if err := client.finish(readyResult, "", nil, readyErr); err != nil {
		return apiInventory{}, err
	}
	nodeResult, err := client.perform(ctx, requestSpec{
		id: fmt.Sprintf("%s.replica-%d.nodes", stage, replica+1), stage: stage, kind: "nodes", replica: replica,
		method: http.MethodGet, path: "/api/v1/networks/" + url.PathEscape(networkID) + "/nodes", expectedStatus: http.StatusOK, auth: true,
	})
	if err != nil {
		return apiInventory{}, err
	}
	var inventory apiInventory
	parseErr := decodeResponse(nodeResult.body, &inventory.nodes)
	if err := client.finish(nodeResult, "", nil, parseErr); err != nil {
		return apiInventory{}, err
	}
	sessionResult, err := client.perform(ctx, requestSpec{
		id: fmt.Sprintf("%s.replica-%d.sessions", stage, replica+1), stage: stage, kind: "sessions", replica: replica,
		method: http.MethodGet, path: "/api/v1/sessions?include_revoked=true&limit=256", expectedStatus: http.StatusOK, auth: true,
	})
	if err != nil {
		return apiInventory{}, err
	}
	parseErr = decodeResponse(sessionResult.body, &inventory.sessions)
	if err := client.finish(sessionResult, "", nil, parseErr); err != nil {
		return apiInventory{}, err
	}
	return inventory, nil
}

func assertReplicaInventories(left, right apiInventory) error {
	if !reflect.DeepEqual(left.nodes, right.nodes) || !reflect.DeepEqual(left.sessions, right.sessions) {
		return errors.New("application replicas returned different exact terminal inventories")
	}
	return nil
}

func assertAPIInventory(inventory apiInventory, terminal TerminalState) error {
	seenNodes := make(map[string]string)
	for _, node := range inventory.nodes {
		if _, tracked := terminal.NodeStates[node.ID]; tracked {
			if _, duplicate := seenNodes[node.ID]; duplicate {
				return errors.New("terminal API repeated a workload node")
			}
			seenNodes[node.ID] = node.Status
		}
	}
	if !reflect.DeepEqual(seenNodes, terminal.NodeStates) {
		return fmt.Errorf("terminal API workload node states=%#v, want %#v", seenNodes, terminal.NodeStates)
	}
	seenSessions := make(map[string]bool)
	for _, session := range inventory.sessions {
		if _, tracked := terminal.SessionRevoked[session.ID]; tracked {
			if _, duplicate := seenSessions[session.ID]; duplicate {
				return errors.New("terminal API repeated a workload session")
			}
			seenSessions[session.ID] = session.RevokedAt != nil
		}
	}
	if !reflect.DeepEqual(seenSessions, terminal.SessionRevoked) {
		return fmt.Errorf("terminal API workload session states=%#v, want %#v", seenSessions, terminal.SessionRevoked)
	}
	return nil
}

func pacedSoak(ctx context.Context, tasks []workloadTask, duration time.Duration) (time.Duration, error) {
	if len(tasks) == 0 || duration <= 0 {
		return 0, errors.New("paced soak requires tasks and a duration")
	}
	started := time.Now()
	semaphore := make(chan struct{}, WorkerConcurrency)
	errorsByTask := make(chan error, len(tasks))
	var wait sync.WaitGroup
	var schedulingErr error
schedule:
	for index, task := range tasks {
		due := started.Add(time.Duration(index) * duration / time.Duration(len(tasks)))
		if delay := time.Until(due); delay > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				schedulingErr = ctx.Err()
				break schedule
			case <-timer.C:
			}
		}
		wait.Add(1)
		go func(task workloadTask) {
			defer wait.Done()
			select {
			case semaphore <- struct{}{}:
				defer func() { <-semaphore }()
				errorsByTask <- task(ctx)
			case <-ctx.Done():
				errorsByTask <- ctx.Err()
			}
		}(task)
	}
	wait.Wait()
	close(errorsByTask)
	elapsed := time.Since(started)
	combined := schedulingErr
	for err := range errorsByTask {
		if err != nil {
			combined = errors.Join(combined, err)
		}
	}
	return elapsed, combined
}

func operationDurations(records []OperationRecord) (writes, reads []time.Duration, successfulLoadWrites int, err error) {
	workloadCount := 0
	writesByReplica := map[int]int{1: 0, 2: 0}
	for _, record := range records {
		if record.Stage != "load" && record.Stage != "soak" {
			continue
		}
		workloadCount++
		if record.Attempts != 1 || record.Error != "" || record.Status != record.ExpectedStatus {
			return nil, nil, 0, fmt.Errorf("workload operation %s is not one successful attempt", record.ID)
		}
		duration := time.Duration(record.DurationMicros) * time.Microsecond
		if record.Write {
			writes = append(writes, duration)
			writesByReplica[record.Replica]++
			if record.Stage == "load" {
				successfulLoadWrites++
			}
		} else if record.Stage == "soak" {
			reads = append(reads, duration)
		}
	}
	if workloadCount != ExpectedWrites+SoakReads {
		return nil, nil, 0, fmt.Errorf("workload operation records=%d, want %d", workloadCount, ExpectedWrites+SoakReads)
	}
	if writesByReplica[1] != ExpectedWrites/2 || writesByReplica[2] != ExpectedWrites/2 {
		return nil, nil, 0, fmt.Errorf("write distribution replica1=%d replica2=%d, want %d each", writesByReplica[1], writesByReplica[2], ExpectedWrites/2)
	}
	return writes, reads, successfulLoadWrites, nil
}

func sortedSessionIDs(values map[string]bool) []string {
	ids := make([]string, 0, len(values))
	for id := range values {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}
