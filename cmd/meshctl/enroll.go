package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"mesh/internal/control"
	"mesh/internal/nodeagent"
)

const (
	defaultAgentState       = "./.mesh-agent/state.json"
	maxKeyFileSize          = 16 << 10
	maxEnrollmentTokenInput = 4 << 10
)

type enrollmentRequest struct {
	Token          string `json:"token"`
	PublicKey      string `json:"public_key"`
	AgentTokenHash string `json:"agent_token_hash"`
}

func enroll(args []string) error {
	return enrollWithIO(args, os.Stdin, os.Getenv)
}

func enrollWithIO(args []string, input io.Reader, getenv func(string) string) error {
	flags := flag.NewFlagSet("enroll", flag.ContinueOnError)
	server := flags.String("server", "http://127.0.0.1:8080", "control plane URL")
	token := flags.String("token", "", "one-time enrollment token (legacy; prefer --token-file -)")
	tokenFile := flags.String("token-file", "", "private enrollment-token file, or - for stdin")
	output := flags.String("output", "./nebula", "managed Nebula bundle directory")
	statePath := flags.String("state", defaultAgentState, "persistent agent state file")
	nebula := flags.String("nebula", "nebula", "nebula binary")
	nebulaCert := flags.String("nebula-cert", "nebula-cert", "nebula-cert binary")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("enroll does not accept positional arguments")
	}
	if getenv == nil {
		getenv = os.Getenv
	}
	enrollmentToken, err := loadEnrollmentToken(strings.TrimSpace(*token), strings.TrimSpace(*tokenFile), input, getenv("MESH_ENROLL_TOKEN"))
	if err != nil {
		return err
	}
	defer func() { enrollmentToken = "" }()

	store, absOutput, err := prepareEnrollmentTargets(*statePath, *output)
	if err != nil {
		return err
	}
	stateLock, err := store.AcquireProcessLock()
	if err != nil {
		return err
	}
	defer stateLock.Close()
	outputLock, err := acquireProcessLock(absOutput, "Nebula bundle output")
	if err != nil {
		return err
	}
	defer outputLock.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	runner := nodeagent.ExecCommandRunner{}
	versionOutput, err := runner.Output(ctx, *nebula, "-version")
	if err != nil {
		return fmt.Errorf("inspect Nebula before enrollment: %w", err)
	}
	if err := nodeagent.EnforceMinimumNebulaVersion(string(versionOutput)); err != nil {
		return err
	}
	validator := nodeagent.BundleValidator{NebulaBinary: *nebula, NebulaCertBinary: *nebulaCert, Runner: runner}
	httpClient := secureHTTPClient()

	journal, journalErr := store.LoadProvisionalEnrollment()
	if journalErr != nil && !errors.Is(journalErr, os.ErrNotExist) {
		return fmt.Errorf("load pending enrollment: %w", journalErr)
	}
	resuming := journalErr == nil
	if resuming {
		if strings.TrimRight(strings.TrimSpace(*server), "/") != journal.ServerURL || absOutput != journal.OutputDir {
			return errors.New("pending enrollment belongs to a different server or output directory")
		}
		if err := nodeagent.PreflightManagedOutput(absOutput); err != nil {
			return fmt.Errorf("preflight pending managed Nebula output before enrollment resume: %w", err)
		}
		if _, err := effectiveEnrollmentToken(enrollmentToken, &journal); err != nil {
			return err
		}
		committed, err := completedProvisionalEnrollment(ctx, store, journal, validator)
		if err != nil {
			return err
		}
		if committed {
			if err := store.ClearProvisionalEnrollment(); err != nil {
				return err
			}
			fmt.Printf("Enrollment was already committed.\nManaged config: %s\nAgent state: %s\n", filepath.Join(absOutput, "current", "config.yml"), store.Path())
			return nil
		}
	} else {
		effectiveToken, err := effectiveEnrollmentToken(enrollmentToken, nil)
		if err != nil {
			return err
		}
		if err := ensureEnrollmentTargetsUnused(store.Path(), absOutput); err != nil {
			return err
		}
		if err := nodeagent.PreflightManagedOutput(absOutput); err != nil {
			return fmt.Errorf("preflight managed Nebula output before enrollment: %w", err)
		}
		plan, err := requestEnrollmentPreflight(ctx, httpClient, *server, effectiveToken)
		if err != nil {
			return err
		}
		checked, err := nodeagent.PreflightEnrollmentEnvironment(ctx, plan)
		if err != nil {
			return err
		}
		if checked.RouteState == nodeagent.EnrollmentRouteUnsupported {
			fmt.Printf("Pre-enrollment DNS check passed for %d lighthouse name(s); local route collision checking is unsupported on this platform.\n", checked.DNSNames)
		} else {
			fmt.Printf("Pre-enrollment route and DNS checks passed for %s and %d lighthouse name(s).\n", plan.NetworkCIDR, checked.DNSNames)
		}
		keypair, err := generateNebulaKeypair(ctx, *nebulaCert)
		if err != nil {
			return err
		}
		defer keypair.Close()
		journal, err = nodeagent.NewProvisionalEnrollment(*server, enrollmentToken, absOutput, string(keypair.privateKey), string(keypair.publicKey))
		if err != nil {
			return err
		}
		if err := store.SaveProvisionalEnrollment(journal); err != nil {
			return fmt.Errorf("persist crash-safe enrollment: %w", err)
		}
		// The fsynced 0600 journal is now the recovery source of truth; remove
		// the short-lived keygen workspace before making a network request.
		if err := keypair.Close(); err != nil {
			return fmt.Errorf("remove temporary key workspace: %w", err)
		}
	}
	agentClient, err := nodeagent.NewClient(journal.ServerURL, journal.Bearer, httpClient)
	if err != nil {
		return err
	}
	payload := enrollmentRequest{
		Token:          journal.EnrollmentToken,
		PublicKey:      journal.PublicKey,
		AgentTokenHash: control.HashToken(journal.Bearer),
	}
	bundle, err := requestEnrollment(ctx, httpClient, agentClient, journal.ServerURL, payload, resuming)
	if err != nil {
		return err
	}
	state, err := nodeagent.NewEnrollmentState(journal.ServerURL, journal.Bearer, journal.OutputDir, journal.PublicKey, bundle)
	if err != nil {
		return fmt.Errorf("build pinned enrollment state: %w", err)
	}
	agentVersion, err := currentMeshAgentVersion()
	if err != nil {
		return err
	}
	agent := &nodeagent.Agent{
		Store: store, HTTPClient: httpClient, Validator: validator,
		Reloader:     nodeagent.ReloadFunc(func(context.Context) error { return nil }),
		AgentVersion: agentVersion,
	}
	if err := stateLock.Close(); err != nil {
		return fmt.Errorf("handoff enrollment state lock: %w", err)
	}
	defer agent.Close()
	if err := agent.InstallEnrollment(ctx, state, bundle, journal.PrivateKey, journal.PublicKey); err != nil {
		return fmt.Errorf("install managed enrollment: %w", err)
	}
	if _, err := store.Load(); err != nil {
		return fmt.Errorf("verify persisted agent state: %w", err)
	}
	if _, err := store.LoadProvisionalEnrollment(); !errors.Is(err, os.ErrNotExist) {
		if err == nil {
			return errors.New("completed enrollment journal was not removed")
		}
		return fmt.Errorf("verify completed enrollment journal removal: %w", err)
	}

	fmt.Printf("Enrolled %s as %s.\n", bundle.Node.Name, bundle.Node.IP)
	fmt.Printf("Managed config: %s\n", filepath.Join(absOutput, "current", "config.yml"))
	fmt.Printf("Agent state: %s\n", store.Path())
	return nil
}

func requestEnrollmentPreflight(ctx context.Context, client *http.Client, server, token string) (control.EnrollmentPreflight, error) {
	endpoint := strings.TrimRight(strings.TrimSpace(server), "/") + "/api/v1/enroll/preflight"
	var raw json.RawMessage
	if err := callContext(ctx, client, http.MethodPost, endpoint, "", struct {
		Token string `json:"token"`
	}{Token: token}, &raw); err != nil {
		return control.EnrollmentPreflight{}, fmt.Errorf("request enrollment preflight: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var plan control.EnrollmentPreflight
	if err := decoder.Decode(&plan); err != nil {
		return control.EnrollmentPreflight{}, fmt.Errorf("decode enrollment preflight: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return control.EnrollmentPreflight{}, errors.New("decode enrollment preflight: response must contain exactly one JSON object")
	}
	if err := control.ValidateEnrollmentPreflight(plan); err != nil {
		return control.EnrollmentPreflight{}, fmt.Errorf("validate enrollment preflight: %w", err)
	}
	return plan, nil
}

func loadEnrollmentToken(explicit, tokenFile string, input io.Reader, environmentToken string) (string, error) {
	explicit = strings.TrimSpace(explicit)
	environmentToken = strings.TrimSpace(environmentToken)
	sources := 0
	for _, present := range []bool{explicit != "", tokenFile != "", environmentToken != ""} {
		if present {
			sources++
		}
	}
	if sources > 1 {
		return "", errors.New("choose only one enrollment-token source: --token, --token-file, or MESH_ENROLL_TOKEN")
	}
	var raw []byte
	var err error
	switch {
	case explicit != "":
		raw = []byte(explicit)
	case environmentToken != "":
		raw = []byte(environmentToken)
	case tokenFile == "-":
		raw, err = readBoundedEnrollmentToken(input)
	case tokenFile != "":
		raw, err = readPrivateEnrollmentTokenFile(tokenFile)
	default:
		return "", nil
	}
	if err != nil {
		return "", err
	}
	value := strings.TrimSpace(string(raw))
	for index := range raw {
		raw[index] = 0
	}
	if !control.ValidBearerToken(value) {
		return "", errors.New("one-time enrollment token is invalid")
	}
	return value, nil
}

func readPrivateEnrollmentTokenFile(path string) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect enrollment-token file: %w", err)
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return nil, errors.New("enrollment-token file must be a regular file, not a symlink")
	}
	if err := validateEnrollmentTokenFileSecurity(before); err != nil {
		return nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open enrollment-token file: %w", err)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) || !opened.Mode().IsRegular() {
		return nil, errors.New("enrollment-token file changed while it was opened")
	}
	if err := validateEnrollmentTokenFileSecurity(opened); err != nil {
		return nil, err
	}
	raw, err := readBoundedEnrollmentToken(file)
	if err != nil {
		return nil, err
	}
	after, statErr := file.Stat()
	visible, pathErr := os.Lstat(path)
	if statErr != nil || pathErr != nil || !os.SameFile(opened, after) || !os.SameFile(opened, visible) ||
		after.Size() != opened.Size() || !after.ModTime().Equal(opened.ModTime()) {
		for index := range raw {
			raw[index] = 0
		}
		return nil, errors.New("enrollment-token file changed while it was read")
	}
	return raw, nil
}

func readBoundedEnrollmentToken(input io.Reader) ([]byte, error) {
	if input == nil {
		return nil, errors.New("enrollment-token input is unavailable")
	}
	raw, err := io.ReadAll(io.LimitReader(input, maxEnrollmentTokenInput+1))
	if err != nil {
		return nil, fmt.Errorf("read enrollment token: %w", err)
	}
	if len(raw) > maxEnrollmentTokenInput {
		for index := range raw {
			raw[index] = 0
		}
		return nil, errors.New("enrollment-token input exceeds the size limit")
	}
	return raw, nil
}

func effectiveEnrollmentToken(provided string, pending *nodeagent.ProvisionalEnrollment) (string, error) {
	provided = strings.TrimSpace(provided)
	if pending != nil {
		if provided != "" && !control.TokenEqual(control.HashToken(pending.EnrollmentToken), provided) {
			return "", errors.New("pending enrollment belongs to a different one-time enrollment token")
		}
		return pending.EnrollmentToken, nil
	}
	if !control.ValidBearerToken(provided) {
		return "", errors.New("a valid one-time enrollment token is required for a new enrollment")
	}
	return provided, nil
}

func completedProvisionalEnrollment(ctx context.Context, store *nodeagent.StateStore, journal nodeagent.ProvisionalEnrollment, validator nodeagent.BundleValidator) (bool, error) {
	state, err := store.Load()
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect partially committed enrollment state: %w", err)
	}
	if state.Bearer != journal.Bearer || state.ServerURL != journal.ServerURL || state.OutputDir != journal.OutputDir {
		return false, errors.New("pending enrollment does not match existing agent state")
	}
	if state.AppliedConfigRevision < 1 {
		return false, nil
	}
	activator := nodeagent.Activator{
		OutputDir: journal.OutputDir, NodeID: state.NodeID, NetworkID: state.NetworkID,
		ConfigSigningPublicKey: state.ConfigSigningPublicKey, CACertificateSHA256: state.CACertificateSHA256, Validator: validator,
		PublicKeyHash: state.PublicKeyHash, Reloader: nodeagent.ReloadFunc(func(context.Context) error { return nil }),
	}
	bundle, err := activator.CurrentBundle(ctx)
	if err != nil {
		return false, nil
	}
	return bundle.Revision == state.AppliedConfigRevision &&
		bundle.Digest == state.AppliedConfigSHA256 &&
		bundle.CertificateGeneration == state.CertificateGeneration &&
		bundle.CertificateFingerprint == state.CertificateFingerprint &&
		bundle.CertificateExpiresAt.Equal(state.CertificateExpiresAt) &&
		bundle.CertificateRenewAfter.Equal(state.CertificateRenewAfter), nil
}

// requestEnrollment retries only when the first result is ambiguous. Both
// POSTs carry the exact same public key and bearer hash. If the server committed
// but its response was lost, the node-scoped bootstrap endpoint recovers the
// signed bundle without ever transmitting the locally generated bearer in a
// request body.
func requestEnrollment(ctx context.Context, client *http.Client, agentClient *nodeagent.Client, server string, payload enrollmentRequest, bootstrapFirst bool) (control.EnrollmentBundle, error) {
	if bootstrapFirst {
		if recovered, err := agentClient.Bootstrap(ctx); err == nil {
			return recovered, nil
		}
	}
	endpoint := strings.TrimRight(strings.TrimSpace(server), "/") + "/api/v1/enroll"
	var bundle control.EnrollmentBundle
	firstErr := callContext(ctx, client, http.MethodPost, endpoint, "", payload, &bundle)
	if firstErr == nil {
		return bundle, nil
	}
	if !ambiguousEnrollmentFailure(firstErr) {
		return control.EnrollmentBundle{}, fmt.Errorf("enroll node: %w", firstErr)
	}
	var retryBundle control.EnrollmentBundle
	retryErr := callContext(ctx, client, http.MethodPost, endpoint, "", payload, &retryBundle)
	if retryErr == nil {
		return retryBundle, nil
	}
	recovered, bootstrapErr := agentClient.Bootstrap(ctx)
	if bootstrapErr == nil {
		return recovered, nil
	}
	return control.EnrollmentBundle{}, errors.Join(
		fmt.Errorf("initial enrollment response was ambiguous: %w", firstErr),
		fmt.Errorf("identical enrollment retry failed: %w", retryErr),
		fmt.Errorf("recover committed enrollment: %w", bootstrapErr),
	)
}

func ambiguousEnrollmentFailure(err error) bool {
	var responseErr *httpResponseError
	return !errors.As(err, &responseErr) || responseErr.StatusCode >= http.StatusInternalServerError
}

func prepareEnrollmentTargets(statePath, output string) (*nodeagent.StateStore, string, error) {
	store, err := nodeagent.NewStateStore(statePath)
	if err != nil {
		return nil, "", err
	}
	absOutput, err := filepath.Abs(output)
	if err != nil {
		return nil, "", fmt.Errorf("resolve bundle output: %w", err)
	}
	absOutput = filepath.Clean(absOutput)
	if pathWithin(absOutput, store.Path()) {
		return nil, "", errors.New("agent state must be outside the managed Nebula bundle directory")
	}
	for _, parent := range []string{filepath.Dir(store.Path()), filepath.Dir(absOutput)} {
		if err := os.MkdirAll(parent, 0o700); err != nil {
			return nil, "", fmt.Errorf("create enrollment parent directory: %w", err)
		}
		info, err := os.Lstat(parent)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, "", errors.New("enrollment parent must be an existing real directory")
		}
	}
	return store, absOutput, nil
}

func ensureEnrollmentTargetsUnused(statePath, output string) error {
	if _, err := os.Lstat(statePath); err == nil {
		return fmt.Errorf("agent state %s already exists", statePath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect agent state: %w", err)
	}
	info, err := os.Lstat(output)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect bundle output: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("bundle output must be a real directory")
	}
	entries, err := os.ReadDir(output)
	if err != nil {
		return fmt.Errorf("inspect bundle output: %w", err)
	}
	if len(entries) != 0 {
		return fmt.Errorf("bundle output %s is not empty", output)
	}
	return nil
}

func pathWithin(parent, child string) bool {
	relative, err := filepath.Rel(filepath.Clean(parent), filepath.Clean(child))
	if err != nil {
		return false
	}
	return relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)))
}

type generatedKeypair struct {
	directory  string
	privateKey []byte
	publicKey  []byte
}

func (k *generatedKeypair) Close() error {
	if k == nil {
		return nil
	}
	clear(k.privateKey)
	clear(k.publicKey)
	k.privateKey = nil
	k.publicKey = nil
	if k.directory == "" {
		return nil
	}
	err := os.RemoveAll(k.directory)
	k.directory = ""
	return err
}

func generateNebulaKeypair(ctx context.Context, nebulaCert string) (*generatedKeypair, error) {
	directory, err := os.MkdirTemp("", "meshctl-keygen-")
	if err != nil {
		return nil, fmt.Errorf("create private key workspace: %w", err)
	}
	keep := false
	defer func() {
		if !keep {
			_ = os.RemoveAll(directory)
		}
	}()
	if err := os.Chmod(directory, 0o700); err != nil {
		return nil, fmt.Errorf("secure private key workspace: %w", err)
	}
	privatePath := filepath.Join(directory, "host.key")
	publicPath := filepath.Join(directory, "host.pub")
	command := exec.CommandContext(ctx, nebulaCert, "keygen", "-out-key", privatePath, "-out-pub", publicPath)
	output, err := command.CombinedOutput()
	if err != nil {
		message := strings.TrimSpace(string(output))
		if len(message) > 512 {
			message = message[:512]
		}
		if message == "" {
			return nil, fmt.Errorf("generate local Nebula keypair: %w", err)
		}
		return nil, fmt.Errorf("generate local Nebula keypair: %s", message)
	}
	privateKey, err := readPrivateKeyFile(privatePath)
	if err != nil {
		return nil, err
	}
	publicKey, err := readPrivateKeyFile(publicPath)
	if err != nil {
		clear(privateKey)
		return nil, err
	}
	keep = true
	return &generatedKeypair{directory: directory, privateKey: privateKey, publicKey: publicKey}, nil
}

func readPrivateKeyFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect generated key: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() > maxKeyFileSize {
		return nil, errors.New("generated key must be a private, bounded regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open generated key: %w", err)
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, maxKeyFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("read generated key: %w", err)
	}
	if len(content) == 0 || len(content) > maxKeyFileSize {
		return nil, errors.New("generated key is empty or too large")
	}
	return content, nil
}

func clear(secret []byte) {
	for index := range secret {
		secret[index] = 0
	}
}
