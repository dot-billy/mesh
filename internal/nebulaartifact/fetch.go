package nebulaartifact

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	connectTimeout        = 10 * time.Second
	tlsHandshakeTimeout   = 10 * time.Second
	responseHeaderTimeout = 15 * time.Second
	totalDownloadTimeout  = 2 * time.Minute
	maxResponseHeaders    = 64 << 10
)

// FetchResult describes an authenticated, verified dependency staging result.
type FetchResult struct {
	Target     Target
	AssetName  string
	OutputDir  string
	FileCount  int
	TotalBytes int64
}

type networkPolicy struct {
	initialURL  string
	initialHost string
	finalHost   string
	allowHTTP   bool
}

// FetchNebula downloads and stages the sole embedded Nebula artifact for the
// requested target. outputDir must not exist. The public API intentionally has
// no URL, digest, version, lock, redirect-host, transport, or retry override.
func FetchNebula(ctx context.Context, goos, goarch, outputDir string) (FetchResult, error) {
	lock, err := EmbeddedLock()
	if err != nil {
		return FetchResult{}, err
	}
	artifact, err := lock.Select(goos, goarch)
	if err != nil {
		return FetchResult{}, err
	}
	policy := networkPolicy{initialURL: artifact.URL, initialHost: lockedInitialHost, finalHost: lockedFinalHost}
	return fetchNebula(ctx, artifact, Target{OS: goos, Arch: goarch}, outputDir, newProductionClient(), policy)
}

func newProductionClient() *http.Client {
	dialer := &net.Dialer{Timeout: connectTimeout, KeepAlive: -1}
	transport := &http.Transport{
		Proxy:                  nil,
		DialContext:            dialer.DialContext,
		ForceAttemptHTTP2:      false,
		DisableKeepAlives:      true,
		DisableCompression:     true,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:    tlsHandshakeTimeout,
		ResponseHeaderTimeout:  responseHeaderTimeout,
		ExpectContinueTimeout:  0,
		MaxResponseHeaderBytes: maxResponseHeaders,
		MaxConnsPerHost:        1,
		MaxIdleConns:           0,
		MaxIdleConnsPerHost:    0,
		WriteBufferSize:        32 << 10,
		ReadBufferSize:         32 << 10,
	}
	return &http.Client{
		Transport: transport,
		Timeout:   totalDownloadTimeout,
		Jar:       nil,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func fetchNebula(ctx context.Context, artifact ArtifactLock, target Target, outputDir string, client *http.Client, policy networkPolicy) (result FetchResult, returnErr error) {
	if client == nil {
		return result, errors.New("HTTP client is nil")
	}
	absOutput, err := filepath.Abs(outputDir)
	if err != nil {
		return result, fmt.Errorf("resolve output path: %w", err)
	}
	absOutput = filepath.Clean(absOutput)
	parentPath, outputName := filepath.Split(absOutput)
	parentPath = filepath.Clean(parentPath)
	if outputName == "" || outputName == "." || outputName == ".." {
		return result, errors.New("output directory must name a new child directory")
	}
	parentInfo, err := os.Lstat(parentPath)
	if err != nil {
		return result, fmt.Errorf("inspect output parent: %w", err)
	}
	if parentInfo.Mode()&os.ModeSymlink != 0 || !parentInfo.IsDir() {
		return result, errors.New("output parent must be an existing directory, not a symlink")
	}
	if err := requireSecureIntakeHost(parentPath, parentInfo); err != nil {
		return result, err
	}
	parentDir, err := os.Open(parentPath)
	if err != nil {
		return result, fmt.Errorf("open output parent: %w", err)
	}
	defer parentDir.Close()
	openedParentInfo, err := parentDir.Stat()
	if err != nil || !os.SameFile(parentInfo, openedParentInfo) {
		return result, errors.New("output parent changed while opening")
	}
	parentRoot, err := os.OpenRoot(parentPath)
	if err != nil {
		return result, fmt.Errorf("open rooted output parent: %w", err)
	}
	defer parentRoot.Close()
	rootInfo, err := parentRoot.Stat(".")
	if err != nil || !os.SameFile(parentInfo, rootInfo) {
		return result, errors.New("rooted output parent does not match inspected directory")
	}
	if _, err := parentRoot.Lstat(outputName); err == nil {
		return result, fmt.Errorf("output directory %q already exists", absOutput)
	} else if !errors.Is(err, os.ErrNotExist) {
		return result, fmt.Errorf("inspect output directory: %w", err)
	}

	archiveName, err := randomPrivateName(".mesh-nebula-archive-")
	if err != nil {
		return result, err
	}
	archiveFile, err := parentRoot.OpenFile(archiveName, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return result, fmt.Errorf("create private archive file: %w", err)
	}
	archiveOwned := true
	defer func() {
		if archiveOwned {
			if err := archiveFile.Close(); err != nil && returnErr == nil {
				returnErr = fmt.Errorf("close archive file: %w", err)
			}
			_ = parentRoot.Remove(archiveName)
		}
	}()

	if err := downloadAuthenticated(ctx, client, policy, artifact, archiveFile); err != nil {
		return result, err
	}
	if _, err := archiveFile.Seek(0, io.SeekStart); err != nil {
		return result, fmt.Errorf("rewind authenticated archive: %w", err)
	}

	stageName, err := randomPrivateName(".mesh-nebula-stage-")
	if err != nil {
		return result, err
	}
	if err := parentRoot.Mkdir(stageName, 0o700); err != nil {
		return result, fmt.Errorf("create private staging directory: %w", err)
	}
	stageOwned := true
	defer func() {
		if stageOwned {
			_ = parentRoot.RemoveAll(stageName)
		}
	}()
	stageRoot, err := parentRoot.OpenRoot(stageName)
	if err != nil {
		return result, fmt.Errorf("open private staging root: %w", err)
	}
	stageRootClosed := false
	defer func() {
		if !stageRootClosed {
			_ = stageRoot.Close()
		}
	}()
	anchoredStageInfo, err := stageRoot.Stat(".")
	if err != nil {
		return result, fmt.Errorf("inspect anchored staging root: %w", err)
	}
	fileCount, totalBytes, err := stageArchive(archiveFile, artifact, stageRoot)
	if err != nil {
		return result, fmt.Errorf("verify and stage archive: %w", err)
	}
	if err := archiveFile.Close(); err != nil {
		return result, fmt.Errorf("close authenticated archive: %w", err)
	}
	if err := parentRoot.Remove(archiveName); err != nil {
		return result, fmt.Errorf("remove private archive: %w", err)
	}
	archiveOwned = false
	if err := syncOpenDirectory(parentDir, parentPath); err != nil {
		return result, fmt.Errorf("sync removal of private archive: %w", err)
	}
	if _, err := parentRoot.Lstat(outputName); err == nil {
		return result, fmt.Errorf("output directory %q appeared during staging", absOutput)
	} else if !errors.Is(err, os.ErrNotExist) {
		return result, fmt.Errorf("recheck output directory: %w", err)
	}
	currentStageInfo, err := parentRoot.Lstat(stageName)
	if err != nil || !currentStageInfo.IsDir() || currentStageInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(anchoredStageInfo, currentStageInfo) {
		return result, errors.New("staging directory identity changed before publication")
	}
	if err := renameNoReplace(parentDir, parentPath, stageName, outputName); err != nil {
		return result, fmt.Errorf("publish verified staging directory without replacement: %w", err)
	}
	publishedInfo, publishErr := parentRoot.Lstat(outputName)
	pathInfo, pathErr := os.Lstat(absOutput)
	latestParentInfo, parentErr := os.Lstat(parentPath)
	securityErr := requireSecureIntakeHost(parentPath, latestParentInfo)
	if publishErr != nil || pathErr != nil || parentErr != nil || securityErr != nil || !os.SameFile(anchoredStageInfo, publishedInfo) || !os.SameFile(anchoredStageInfo, pathInfo) || !os.SameFile(openedParentInfo, latestParentInfo) {
		_ = stageRoot.Close()
		stageRootClosed = true
		removeErr := parentRoot.RemoveAll(outputName)
		syncErr := syncOpenDirectory(parentDir, parentPath)
		stageOwned = false
		return result, fmt.Errorf("published output path identity or ancestry changed; verified output removed: publish=%v path=%v parent=%v security=%v remove=%v sync=%v", publishErr, pathErr, parentErr, securityErr, removeErr, syncErr)
	}
	if err := stageRoot.Close(); err != nil {
		stageRootClosed = true
		removeErr := parentRoot.RemoveAll(outputName)
		syncErr := syncOpenDirectory(parentDir, parentPath)
		stageOwned = false
		return result, fmt.Errorf("close published staging root: %w; verified output removed: remove=%v sync=%v", err, removeErr, syncErr)
	}
	stageRootClosed = true
	if err := syncOpenDirectory(parentDir, parentPath); err != nil {
		removeErr := parentRoot.RemoveAll(outputName)
		cleanupSyncErr := syncOpenDirectory(parentDir, parentPath)
		stageOwned = false
		return result, fmt.Errorf("sync published output parent: %w; verified output removed: remove=%v cleanup-sync=%v", err, removeErr, cleanupSyncErr)
	}
	stageOwned = false
	return FetchResult{Target: target, AssetName: artifact.Name, OutputDir: absOutput, FileCount: fileCount, TotalBytes: totalBytes}, nil
}

func downloadAuthenticated(ctx context.Context, client *http.Client, policy networkPolicy, artifact ArtifactLock, destination *os.File) error {
	if err := validateRequestURL(artifact.URL, policy.initialURL, policy.initialHost, policy.allowHTTP, false); err != nil {
		return fmt.Errorf("initial URL: %w", err)
	}
	response, err := doRequest(ctx, client, artifact.URL)
	if err != nil {
		return fmt.Errorf("initial request: %w", err)
	}
	if response.Body == nil {
		return errors.New("initial response has no body")
	}
	if !redirectStatus(response.StatusCode) {
		_ = response.Body.Close()
		return fmt.Errorf("initial endpoint returned %s, want exactly one redirect", response.Status)
	}
	locations := response.Header.Values("Location")
	_ = response.Body.Close()
	if len(locations) != 1 || locations[0] == "" {
		return errors.New("redirect response must have exactly one Location header")
	}
	location := locations[0]
	redirectURL, err := url.Parse(location)
	if err != nil || !redirectURL.IsAbs() {
		return errors.New("redirect Location must be an absolute URL")
	}
	if err := validateRequestURL(redirectURL.String(), "", policy.finalHost, policy.allowHTTP, true); err != nil {
		return fmt.Errorf("redirect URL: %w", err)
	}
	response, err = doRequest(ctx, client, redirectURL.String())
	if err != nil {
		return fmt.Errorf("asset request: %w", err)
	}
	if response.Body == nil {
		return errors.New("asset response has no body")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("asset endpoint returned %s", response.Status)
	}
	if encoding := response.Header.Get("Content-Encoding"); encoding != "" && !strings.EqualFold(encoding, "identity") {
		return fmt.Errorf("asset Content-Encoding %q is not allowed", cleanErrorText(encoding))
	}
	if response.ContentLength != artifact.Size {
		return fmt.Errorf("asset Content-Length is %d, want %d", response.ContentLength, artifact.Size)
	}
	hash := sha256.New()
	written, err := io.Copy(io.MultiWriter(destination, hash), io.LimitReader(response.Body, artifact.Size+1))
	if err != nil {
		return fmt.Errorf("stream asset: %w", err)
	}
	if written != artifact.Size {
		return fmt.Errorf("asset size is %d bytes, want %d", written, artifact.Size)
	}
	actualHash := hex.EncodeToString(hash.Sum(nil))
	if actualHash != artifact.SHA256 {
		return fmt.Errorf("asset SHA-256 is %s, want %s", actualHash, artifact.SHA256)
	}
	if err := destination.Sync(); err != nil {
		return fmt.Errorf("sync authenticated archive: %w", err)
	}
	return nil
}

func doRequest(ctx context.Context, client *http.Client, address string) (*http.Response, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/octet-stream")
	request.Header.Set("Accept-Encoding", "identity")
	request.Header.Set("User-Agent", "mesh-deps/nebula-v1.10.3")
	return client.Do(request)
}

func validateRequestURL(raw, exact, host string, allowHTTP, allowQuery bool) error {
	if exact != "" && raw != exact {
		return errors.New("URL differs from the embedded lock")
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Opaque != "" || parsed.User != nil || parsed.Fragment != "" {
		return errors.New("URL contains unsupported authority or fragment data")
	}
	if parsed.Scheme != "https" && !(allowHTTP && parsed.Scheme == "http") {
		return errors.New("URL must use HTTPS")
	}
	if parsed.Hostname() != host || !standardPort(parsed, allowHTTP) {
		return errors.New("URL host or port is not allowed")
	}
	if parsed.Path == "" || (!allowQuery && (parsed.RawQuery != "" || parsed.ForceQuery)) {
		return errors.New("URL path or query is not allowed")
	}
	return nil
}

func standardPort(parsed *url.URL, allowHTTP bool) bool {
	port := parsed.Port()
	if port == "" || parsed.Scheme == "https" && port == "443" {
		return true
	}
	return allowHTTP && parsed.Scheme == "http" && port == "80"
}

func redirectStatus(status int) bool {
	switch status {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	default:
		return false
	}
}

func randomPrivateName(prefix string) (string, error) {
	var random [16]byte
	if _, err := io.ReadFull(rand.Reader, random[:]); err != nil {
		return "", fmt.Errorf("read cryptographic randomness: %w", err)
	}
	return prefix + hex.EncodeToString(random[:]), nil
}

func cleanErrorText(value string) string { return strings.ReplaceAll(value, "\n", " ") }
