// Package darwinnodepackage owns the immutable payload and invocation policy
// for the protected Mesh Node flat installer package.
package darwinnodepackage

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"strings"
	"unicode/utf8"
)

const (
	Schema            = "mesh-darwin-node-package-policy-v2"
	FramePrefix       = "MESH_DARWIN_NODE_PACKAGE_V2."
	FrameSuffix       = ".END_MESH_DARWIN_NODE_PACKAGE_V2"
	DevelopmentPolicy = "mesh-development-no-darwin-node-package-policy"

	maximumPolicyJSON  = 8 << 10
	maximumPolicyFrame = 16 << 10

	PackageInstallLocation = "/Library/Application Support/Mesh"
)

var (
	packageIdentifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{2,127}$`)
)

// Identity is replaced exactly once in a protected package build. The
// development sentinel is intentionally not parseable.
var Identity = DevelopmentPolicy

type PolicySpec struct {
	PackageIdentifier      string
	PackageRootPath        string
	InstalledBootstrapPath string
	PackageSnapshotPath    string
}

type policyDocument struct {
	Schema                     string `json:"schema"`
	PackageIdentifier          string `json:"package_identifier"`
	PackageInstallLocation     string `json:"package_install_location"`
	PackageRootPath            string `json:"package_root_path"`
	InstalledBootstrapPath     string `json:"installed_bootstrap_path"`
	PackageSnapshotPath        string `json:"package_snapshot_path"`
	RequireCompiledPostinstall bool   `json:"require_compiled_postinstall"`
	RequireRootWheel           bool   `json:"require_root_wheel"`
	RequireNotarization        bool   `json:"require_notarization"`
}

type Policy struct {
	PackageIdentifier      string
	PackageInstallLocation string
	PackageRootPath        string
	InstalledBootstrapPath string
	PackageSnapshotPath    string
	SHA256                 string
}

func EncodePolicy(spec PolicySpec) (string, Policy, error) {
	document := policyDocument{
		Schema: Schema, PackageIdentifier: spec.PackageIdentifier,
		PackageInstallLocation:     PackageInstallLocation,
		PackageRootPath:            spec.PackageRootPath,
		InstalledBootstrapPath:     spec.InstalledBootstrapPath,
		PackageSnapshotPath:        spec.PackageSnapshotPath,
		RequireCompiledPostinstall: true,
		RequireRootWheel:           true,
		RequireNotarization:        true,
	}
	raw, err := json.Marshal(document)
	if err != nil {
		return "", Policy{}, fmt.Errorf("encode Darwin node package policy: %w", err)
	}
	if len(raw) > maximumPolicyJSON {
		return "", Policy{}, errors.New("Darwin node package policy exceeds its JSON size bound")
	}
	policy, err := parsePolicyDocument(raw)
	if err != nil {
		return "", Policy{}, err
	}
	frame := FramePrefix + base64.RawURLEncoding.EncodeToString(raw) + FrameSuffix
	if len(frame) > maximumPolicyFrame {
		return "", Policy{}, errors.New("Darwin node package policy exceeds its frame size bound")
	}
	return frame, policy, nil
}

func LoadPolicy() (Policy, error) {
	if Identity == DevelopmentPolicy {
		return Policy{}, errors.New("no Darwin node package policy is compiled into this build")
	}
	return ParsePolicyIdentity(Identity)
}

func ParsePolicyIdentity(frame string) (Policy, error) {
	if len(frame) == 0 || len(frame) > maximumPolicyFrame ||
		!strings.HasPrefix(frame, FramePrefix) || !strings.HasSuffix(frame, FrameSuffix) {
		return Policy{}, errors.New("Darwin node package policy does not have the exact v2 frame")
	}
	encoded := strings.TrimSuffix(strings.TrimPrefix(frame, FramePrefix), FrameSuffix)
	if encoded == "" {
		return Policy{}, errors.New("Darwin node package policy payload is empty")
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(raw) == 0 || len(raw) > maximumPolicyJSON ||
		base64.RawURLEncoding.EncodeToString(raw) != encoded {
		return Policy{}, errors.New("Darwin node package policy must be canonical unpadded base64url")
	}
	return parsePolicyDocument(raw)
}

func parsePolicyDocument(raw []byte) (Policy, error) {
	if len(raw) == 0 || len(raw) > maximumPolicyJSON || !utf8.Valid(raw) {
		return Policy{}, errors.New("Darwin node package policy JSON is empty, oversized, or invalid UTF-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var document policyDocument
	if err := decoder.Decode(&document); err != nil {
		return Policy{}, fmt.Errorf("decode Darwin node package policy: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Policy{}, errors.New("Darwin node package policy contains trailing data")
	}
	if document.Schema != Schema || !document.RequireCompiledPostinstall ||
		!document.RequireRootWheel || !document.RequireNotarization {
		return Policy{}, errors.New("Darwin node package policy security contract is invalid")
	}
	if !canonicalIdentifier(document.PackageIdentifier) {
		return Policy{}, errors.New("Darwin node package identifier is not canonical")
	}
	if document.PackageInstallLocation != PackageInstallLocation {
		return Policy{}, errors.New("Darwin node package install location is not the fixed Mesh namespace")
	}
	if !boundedPath(document.PackageRootPath, PackageInstallLocation) ||
		path.Dir(document.PackageRootPath) != PackageInstallLocation {
		return Policy{}, errors.New("Darwin node package root is not one direct Mesh-owned package directory")
	}
	if !boundedPath(document.InstalledBootstrapPath, document.PackageRootPath) ||
		path.Dir(document.InstalledBootstrapPath) != document.PackageRootPath ||
		path.Base(document.InstalledBootstrapPath) != "mesh-install" {
		return Policy{}, errors.New("Darwin node package bootstrap is not the exact package-root executable")
	}
	if !boundedPath(document.PackageSnapshotPath, document.PackageRootPath) ||
		path.Dir(document.PackageSnapshotPath) != document.PackageRootPath ||
		path.Base(document.PackageSnapshotPath) != "snapshot" {
		return Policy{}, errors.New("Darwin node package snapshot is not the exact package-root snapshot directory")
	}
	canonical, err := json.Marshal(document)
	if err != nil || !bytes.Equal(canonical, raw) {
		return Policy{}, errors.Join(err, errors.New("Darwin node package policy JSON is not canonical"))
	}
	digest := sha256.Sum256(raw)
	return Policy{
		PackageIdentifier:      document.PackageIdentifier,
		PackageInstallLocation: document.PackageInstallLocation,
		PackageRootPath:        document.PackageRootPath,
		InstalledBootstrapPath: document.InstalledBootstrapPath,
		PackageSnapshotPath:    document.PackageSnapshotPath,
		SHA256:                 hex.EncodeToString(digest[:]),
	}, nil
}

func canonicalIdentifier(value string) bool {
	return packageIdentifierPattern.MatchString(value) &&
		!strings.Contains(value, "..") && !strings.HasSuffix(value, ".")
}

func boundedPath(value, namespace string) bool {
	return value != "" && path.IsAbs(value) && path.Clean(value) == value &&
		value != namespace && strings.HasPrefix(value, namespace+"/") &&
		!strings.ContainsRune(value, '\x00')
}
