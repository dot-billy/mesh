package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	maximumCAFileSize = 1 << 20
	maximumReadyBody  = 256
)

type healthcheckConfig struct {
	URL        string
	CAFile     string
	ServerName string
	Timeout    time.Duration
}

type readyResponse struct {
	Status string `json:"status"`
}

func main() {
	if err := run(os.Args[1:], os.Getenv); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "mesh-healthcheck:", err)
		os.Exit(1)
	}
}

func run(arguments []string, getenv func(string) string) error {
	config, err := parseHealthcheckConfig(arguments, getenv)
	if err != nil {
		return err
	}
	roots, err := readRootCAs(config.CAFile)
	if err != nil {
		return err
	}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: (&net.Dialer{
			Timeout:   config.Timeout,
			KeepAlive: -1,
		}).DialContext,
		DisableCompression: true,
		DisableKeepAlives:  true,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    roots,
			ServerName: config.ServerName,
		},
		TLSHandshakeTimeout: config.Timeout,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		Timeout:   config.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("redirects are not accepted")
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), config.Timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, config.URL, nil)
	if err != nil {
		return errors.New("construct readiness request")
	}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("readiness request failed: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("readiness returned HTTP %d", response.StatusCode)
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return errors.New("readiness returned an invalid content type")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maximumReadyBody+1))
	if err != nil || len(raw) == 0 || len(raw) > maximumReadyBody {
		return errors.New("readiness returned an empty or oversized body")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var payload readyResponse
	if err := decoder.Decode(&payload); err != nil {
		return errors.New("readiness returned invalid JSON")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("readiness returned trailing content")
	}
	if payload.Status != "ready" {
		return errors.New("readiness did not report ready")
	}
	return nil
}

func parseHealthcheckConfig(arguments []string, getenv func(string) string) (healthcheckConfig, error) {
	config := healthcheckConfig{
		URL:        strings.TrimSpace(getenv("MESH_HEALTHCHECK_URL")),
		CAFile:     strings.TrimSpace(getenv("MESH_HEALTHCHECK_CA_FILE")),
		ServerName: strings.TrimSpace(getenv("MESH_HEALTHCHECK_SERVER_NAME")),
		Timeout:    3 * time.Second,
	}
	flags := flag.NewFlagSet("mesh-healthcheck", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&config.URL, "url", config.URL, "exact local HTTPS readiness URL")
	flags.StringVar(&config.CAFile, "ca-file", config.CAFile, "PEM trust roots for the local TLS certificate")
	flags.StringVar(&config.ServerName, "server-name", config.ServerName, "expected TLS DNS name or IP address")
	flags.DurationVar(&config.Timeout, "timeout", config.Timeout, "positive readiness deadline up to ten seconds")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return healthcheckConfig{}, errors.New("invalid healthcheck arguments")
	}
	if config.Timeout <= 0 || config.Timeout > 10*time.Second {
		return healthcheckConfig{}, errors.New("healthcheck timeout must be positive and no more than ten seconds")
	}
	parsed, err := url.Parse(config.URL)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "/readyz" || parsed.RawPath != "" {
		return healthcheckConfig{}, errors.New("healthcheck URL must be an exact HTTPS /readyz URL without credentials, query, or fragment")
	}
	host := parsed.Hostname()
	port := parsed.Port()
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() || port == "" {
		return healthcheckConfig{}, errors.New("healthcheck URL must use an explicit loopback IP and port")
	}
	if config.ServerName == "" || strings.TrimSpace(config.ServerName) != config.ServerName || strings.ContainsAny(config.ServerName, "/?#@") {
		return healthcheckConfig{}, errors.New("healthcheck server name is required and invalid")
	}
	if config.CAFile == "" || !filepath.IsAbs(config.CAFile) || filepath.Clean(config.CAFile) != config.CAFile {
		return healthcheckConfig{}, errors.New("healthcheck CA file must be a clean absolute path")
	}
	return config, nil
}

func readRootCAs(path string) (*x509.CertPool, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("open healthcheck CA file")
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maximumCAFileSize+1))
	if err != nil || len(raw) < 1 || len(raw) > maximumCAFileSize {
		return nil, errors.New("read bounded healthcheck CA file")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(raw) {
		return nil, errors.New("healthcheck CA file contains no trusted certificate")
	}
	return roots, nil
}
