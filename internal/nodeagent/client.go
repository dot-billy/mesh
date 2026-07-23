package nodeagent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"mesh/internal/control"
	"mesh/internal/runtimetelemetry"
)

const maxResponseSize = 2 << 20

var ErrRuntimeTelemetryUnsupported = errors.New("mesh server does not support runtime telemetry")

type APIError struct {
	StatusCode int
	Message    string
}

func (e *APIError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("mesh server returned HTTP %d", e.StatusCode)
	}
	return fmt.Sprintf("mesh server returned HTTP %d: %s", e.StatusCode, e.Message)
}

type ConfigResponse struct {
	Config      control.AgentConfig
	ETag        string
	NotModified bool
}

// Client is an authenticated node-scoped API client. Redirects are rejected so
// a bearer can never be forwarded to an unexpected or downgraded endpoint.
type Client struct {
	baseURL string
	bearer  string
	http    *http.Client
}

func NewClient(serverURL, bearer string, httpClient *http.Client) (*Client, error) {
	baseURL, err := normalizeServerURL(serverURL)
	if err != nil {
		return nil, err
	}
	bearer = strings.TrimSpace(bearer)
	if !control.ValidBearerToken(bearer) {
		return nil, errors.New("agent bearer is missing or too short")
	}
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	clientCopy := *httpClient
	if clientCopy.Timeout == 0 {
		clientCopy.Timeout = 30 * time.Second
	}
	clientCopy.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &Client{baseURL: baseURL, bearer: bearer, http: &clientCopy}, nil
}

func (c *Client) GetConfig(ctx context.Context, etag string) (ConfigResponse, error) {
	req, err := c.request(ctx, http.MethodGet, "/api/v1/agent/config", nil)
	if err != nil {
		return ConfigResponse{}, err
	}
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	response, err := c.http.Do(req)
	if err != nil {
		return ConfigResponse{}, fmt.Errorf("get signed config: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotModified {
		if _, err := readLimited(response.Body); err != nil {
			return ConfigResponse{}, err
		}
		return ConfigResponse{ETag: response.Header.Get("ETag"), NotModified: true}, nil
	}
	if response.StatusCode != http.StatusOK {
		return ConfigResponse{}, responseError(response)
	}
	var config control.AgentConfig
	if err := decodeResponse(response.Body, &config); err != nil {
		return ConfigResponse{}, fmt.Errorf("decode signed config: %w", err)
	}
	return ConfigResponse{Config: config, ETag: response.Header.Get("ETag")}, nil
}

func (c *Client) Bootstrap(ctx context.Context) (control.EnrollmentBundle, error) {
	req, err := c.request(ctx, http.MethodGet, "/api/v1/agent/bootstrap", nil)
	if err != nil {
		return control.EnrollmentBundle{}, err
	}
	response, err := c.http.Do(req)
	if err != nil {
		return control.EnrollmentBundle{}, fmt.Errorf("get recoverable agent bootstrap: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return control.EnrollmentBundle{}, responseError(response)
	}
	var bundle control.EnrollmentBundle
	if err := decodeResponse(response.Body, &bundle); err != nil {
		return control.EnrollmentBundle{}, fmt.Errorf("decode agent bootstrap: %w", err)
	}
	return bundle, nil
}

// RecoverAgent exchanges a separately scoped administrative recovery token for
// a signed agent-credential recovery result. The possibly expired agent bearer
// is deliberately omitted: the recovery token in the JSON body is the sole
// authorization for this endpoint.
func (c *Client) RecoverAgent(ctx context.Context, input control.RecoverAgentInput) (control.AgentRecoveryBundle, error) {
	req, err := c.request(ctx, http.MethodPost, "/api/v1/agent/recover", input)
	if err != nil {
		return control.AgentRecoveryBundle{}, err
	}
	req.Header.Del("Authorization")
	response, err := c.http.Do(req)
	if err != nil {
		return control.AgentRecoveryBundle{}, fmt.Errorf("recover agent credential: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return control.AgentRecoveryBundle{}, responseError(response)
	}
	var bundle control.AgentRecoveryBundle
	if err := decodeResponse(response.Body, &bundle); err != nil {
		return control.AgentRecoveryBundle{}, fmt.Errorf("decode agent credential recovery: %w", err)
	}
	return bundle, nil
}

func (c *Client) Heartbeat(ctx context.Context, input control.HeartbeatInput) error {
	req, err := c.request(ctx, http.MethodPost, "/api/v1/agent/heartbeat", input)
	if err != nil {
		return err
	}
	response, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("post agent heartbeat: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		return responseError(response)
	}
	_, err = readLimited(response.Body)
	return err
}

func (c *Client) ReportConfigApplyFailure(ctx context.Context, input control.ConfigApplyFailureInput) error {
	req, err := c.request(ctx, http.MethodPost, "/api/v1/agent/config-apply-failure", input)
	if err != nil {
		return err
	}
	response, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("post config activation failure: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		return responseError(response)
	}
	_, err = readLimited(response.Body)
	return err
}

// ReportRuntimeTelemetry posts the separately versioned observation envelope
// after its lifecycle heartbeat has been accepted. A 404 or method-only 405 is
// a deliberate mixed-version signal: old servers do not register this optional
// endpoint (their static GET route can produce the latter).
func (c *Client) ReportRuntimeTelemetry(ctx context.Context, input runtimetelemetry.ReportInput) error {
	if input.HeartbeatSequence < 1 {
		return fmt.Errorf("runtime telemetry heartbeat sequence is invalid: %w", runtimetelemetry.ErrInvalid)
	}
	if err := runtimetelemetry.ValidateObservation(input.Observation); err != nil {
		return err
	}
	req, err := c.request(ctx, http.MethodPost, "/api/v1/agent/runtime-telemetry", input)
	if err != nil {
		return err
	}
	response, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("post agent runtime telemetry: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound || response.StatusCode == http.StatusMethodNotAllowed {
		if _, err := readLimited(response.Body); err != nil {
			return err
		}
		return ErrRuntimeTelemetryUnsupported
	}
	if response.StatusCode != http.StatusNoContent {
		return responseError(response)
	}
	_, err = readLimited(response.Body)
	return err
}

func (c *Client) RenewCertificate(ctx context.Context, publicKey string) (control.RenewalBundle, error) {
	input := struct {
		PublicKey string `json:"public_key"`
	}{PublicKey: publicKey}
	req, err := c.request(ctx, http.MethodPost, "/api/v1/agent/certificate/renew", input)
	if err != nil {
		return control.RenewalBundle{}, err
	}
	response, err := c.http.Do(req)
	if err != nil {
		return control.RenewalBundle{}, fmt.Errorf("renew node certificate: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return control.RenewalBundle{}, responseError(response)
	}
	var bundle control.RenewalBundle
	if err := decodeResponse(response.Body, &bundle); err != nil {
		return control.RenewalBundle{}, fmt.Errorf("decode certificate renewal: %w", err)
	}
	return bundle, nil
}

func (c *Client) RotateCredential(ctx context.Context, newTokenHash string) (control.CredentialRotation, error) {
	input := struct {
		NewTokenHash string `json:"new_token_hash"`
	}{NewTokenHash: newTokenHash}
	req, err := c.request(ctx, http.MethodPost, "/api/v1/agent/credentials/rotate", input)
	if err != nil {
		return control.CredentialRotation{}, err
	}
	response, err := c.http.Do(req)
	if err != nil {
		return control.CredentialRotation{}, fmt.Errorf("rotate agent credential: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return control.CredentialRotation{}, responseError(response)
	}
	var rotation control.CredentialRotation
	if err := decodeResponse(response.Body, &rotation); err != nil {
		return control.CredentialRotation{}, fmt.Errorf("decode credential rotation: %w", err)
	}
	return rotation, nil
}

func (c *Client) request(ctx context.Context, method, path string, input any) (*http.Request, error) {
	var body io.Reader
	if input != nil {
		encoded, err := json.Marshal(input)
		if err != nil {
			return nil, fmt.Errorf("encode agent request: %w", err)
		}
		body = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return nil, fmt.Errorf("create agent request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.bearer)
	if input != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return req, nil
}

func responseError(response *http.Response) error {
	body, err := readLimited(response.Body)
	if err != nil {
		return err
	}
	var payload struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(body, &payload)
	message := strings.TrimSpace(payload.Error)
	if len(message) > 512 {
		message = message[:512]
	}
	return &APIError{StatusCode: response.StatusCode, Message: message}
}

func decodeResponse(reader io.Reader, output any) error {
	body, err := readLimited(reader)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return err
	}
	return ensureJSONEOF(decoder)
}

func readLimited(reader io.Reader) ([]byte, error) {
	limited := io.LimitReader(reader, maxResponseSize+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("read mesh server response: %w", err)
	}
	if len(body) > maxResponseSize {
		return nil, errors.New("mesh server response exceeds size limit")
	}
	return body, nil
}
