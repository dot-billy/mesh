# Authenticated Online Release Retrieval Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add threshold-authenticated HTTPS release retrieval to the Linux installer and expose the exact install, stdin enrollment, and activation workflow in the Mesh web app.

**Architecture:** A new `internal/onlinerelease` package owns the unsigned, bounded metadata transport schema, canonical bundle URL, and hardened downloader. `internal/linuxinstall` owns root-private intake and performs a short pre-download verification plus the existing `ApplySnapshot` verification after download. The server only publishes an informational configured URL; browser code validates it and renders commands without embedding the enrollment token.

**Tech Stack:** Go 1.26 standard library, existing Ed25519 release verifier, Linux `os.Root`/`flock`/`O_TMPFILE` patterns, `net/http`, vanilla browser JavaScript, Node test runner, Bash, Docker/systemd, OpenSSL/Python HTTPS smoke fixture.

---

## Execution note

`/home/uwadmin/mesh` is not currently a Git checkout. Every commit checkpoint
below is required when execution occurs in a checkout; in the present workspace
skip only the `git add`/`git commit` commands and never initialize Git. Do not
skip tests or combine implementation steps merely because commits are
unavailable.

## File map

### New files

- `internal/onlinerelease/bundle.go` — exact online bundle model, canonical
  encoding, strict decoding, limits, and deep-copy boundary.
- `internal/onlinerelease/bundle_test.go` — schema, Unicode, duplicate-field,
  base64, canonicality, size, count, collision, and ownership tests.
- `internal/onlinerelease/url.go` — one canonical public bundle-URL parser used
  by installer and server.
- `internal/onlinerelease/url_test.go` — accepted and rejected URL matrix.
- `internal/onlinerelease/client.go` — hardened production client, bounded
  metadata fetch, and authenticated artifact streaming.
- `internal/onlinerelease/client_test.go` — transport, timeout, redirect,
  compression, size, digest, proxy, and cancellation tests.
- `cmd/mesh-release/assemble_online_bundle_linux.go` — stable-input,
  deterministic, create-only publisher command.
- `cmd/mesh-release/assemble_online_bundle_linux_test.go` — publisher
  determinism, races, collisions, modes, and readback tests.
- `cmd/mesh-release/assemble_online_bundle_other.go` — explicit non-Linux
  refusal.
- `internal/linuxinstall/online_intake.go` — dedicated root-private intake lock,
  child allocation, rooted cleanup, and snapshot materialization.
- `internal/linuxinstall/online_intake_test.go` — ownership, mode, name,
  mutation, crash-leftover, unknown-entry, and cleanup tests.
- `internal/linuxinstall/online.go` — two-pass online orchestration and
  dependency seam.
- `internal/linuxinstall/online_test.go` — ordering, no-early-fetch, state race,
  cancellation, pending transaction, and final-apply tests.
- `internal/httpapi/install_guide.go` — strict response model and authenticated
  handler.
- `internal/httpapi/install_guide_test.go` — constructor, auth, exact JSON, and
  unset/configured response tests.
- `internal/httpapi/web/install-guide.js` — strict browser model, shell quoting,
  and command construction.
- `internal/httpapi/webtest/install-guide.test.js` — model and command security
  tests.

### Modified files

- `internal/release/strictjson.go` — export the already-tested strict JSON
  syntax validator without changing release parsing.
- `internal/release/artifact.go` — expose one artifact-reference validator for
  the authenticated downloader.
- `internal/release/verify.go` — reuse that validator during manifest parsing.
- `internal/release/release_test.go` — prove exported strict validation retains
  duplicate/Unicode/trailing-value behavior.
- `cmd/mesh-release/main.go` — dispatch and usage for
  `assemble-online-bundle`.
- `cmd/mesh-release/main_test.go` — command-surface regression.
- `cmd/mesh-install/main.go` — dispatch `install-online` to production
  orchestration.
- `cmd/mesh-install/main_test.go` — exact CLI arity and injected execution.
- `cmd/mesh-server/storage_config.go` — optional
  `--linux-install-bundle-url` field and validation.
- `cmd/mesh-server/storage_config_test.go` — configuration matrix.
- `cmd/mesh-server/main.go` — pass the validated URL into `httpapi.Options`.
- `internal/httpapi/server.go` — store the informational URL and register the
  admin endpoint.
- `internal/httpapi/server_test.go` — constructor parity and route regression.
- `internal/httpapi/web/index.html` — load the browser model and render three
  enrollment steps with copy controls.
- `internal/httpapi/web/app.js` — load the guide, maintain fallback state, and
  populate commands.
- `internal/httpapi/web/style.css` — accessible command-step and fallback
  presentation.
- `scripts/linux-install-smoke.sh` — real HTTPS first install, negative cases,
  online upgrade, state race, cleanup, and offline regression.
- `packaging/systemd/proof-fedora42.Dockerfile` — add the HTTPS fixture runtime
  and advance its proof-image identity.
- `docs/release-trust.md` — online format, operator publication, command, and
  remaining bootstrap boundary.
- `packaging/systemd/README.md` — online install and correct activation flow.
- `docs/security.md` — implemented retrieval boundary and retained gaps.
- `docs/roadmap.md` — mark authenticated online retrieval implemented only
  after live proof.

## Task 1: Export strict JSON syntax validation

**Files:**
- Modify: `internal/release/strictjson.go`
- Modify: `internal/release/release_test.go`

- [x] **Step 1: Write the failing exported-contract test**

Append this table-driven test to `internal/release/release_test.go`:

```go
func TestValidateStrictJSONRejectsAmbiguousSyntax(t *testing.T) {
	valid := []byte(`{"schema":"example","value":[1,true,null]}`)
	if err := ValidateStrictJSON(valid); err != nil {
		t.Fatalf("valid strict JSON: %v", err)
	}
	for name, raw := range map[string][]byte{
		"duplicate":       []byte(`{"schema":"a","schema":"b"}`),
		"trailing":        []byte(`{"schema":"a"}{}`),
		"invalid utf8":    {'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'},
		"high surrogate":  []byte(`{"x":"\ud800"}`),
		"low surrogate":   []byte(`{"x":"\udc00"}`),
	} {
		t.Run(name, func(t *testing.T) {
			if err := ValidateStrictJSON(raw); err == nil {
				t.Fatal("ambiguous JSON accepted")
			}
		})
	}
}
```

- [x] **Step 2: Run the focused test and verify the symbol is missing**

Run:

```bash
go test ./internal/release -run TestValidateStrictJSONRejectsAmbiguousSyntax -count=1
```

Expected: build failure containing `undefined: ValidateStrictJSON`.

- [x] **Step 3: Add the read-only exported wrapper**

Add directly above `validateJSONSyntax` in
`internal/release/strictjson.go`:

```go
// ValidateStrictJSON applies the release parser's duplicate-field, Unicode,
// delimiter, and single-value rules without decoding any schema semantics.
// Callers must still enforce an independent byte bound before invoking it.
func ValidateStrictJSON(raw []byte) error {
	return validateJSONSyntax(raw)
}
```

Do not rename or change any existing private helper.

- [x] **Step 4: Run release tests**

Run:

```bash
go test ./internal/release -count=1
```

Expected: `ok   mesh/internal/release`.

- [x] **Step 5: Commit the strict validator checkpoint (skipped: workspace has no Git metadata)**

```bash
git add internal/release/strictjson.go internal/release/release_test.go
git commit -m "refactor: expose strict release JSON validation"
```

## Task 2: Implement the exact online bundle schema

**Files:**
- Create: `internal/onlinerelease/bundle.go`
- Create: `internal/onlinerelease/bundle_test.go`

- [x] **Step 1: Write failing canonical round-trip and rejection tests**

Create `internal/onlinerelease/bundle_test.go` with package
`onlinerelease` and this core fixture/test; add subtests for every mutation in
the `invalid` map:

```go
package onlinerelease

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	releasetrust "mesh/internal/release"
)

func testBundle() Bundle {
	return Bundle{
		ChannelManifest:   []byte(`{"schema":"mesh-channel-manifest-v1"}`),
		ChannelSignatures: [][]byte{[]byte(`{"manifest_type":"channel","signature":"a"}`)},
		ReleaseManifest:   []byte(`{"schema":"mesh-release-manifest-v1"}`),
		ReleaseSignatures: [][]byte{[]byte(`{"manifest_type":"release","signature":"b"}`)},
	}
}

func TestBundleExactCanonicalRoundTrip(t *testing.T) {
	want := testBundle()
	raw, err := Encode(want)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) == 0 || raw[len(raw)-1] != '\n' || bytes.Count(raw, []byte{'\n'}) != 1 {
		t.Fatalf("bundle is not one compact JSON line: %q", raw)
	}
	got, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.ChannelManifest, want.ChannelManifest) ||
		!bytes.Equal(got.ReleaseManifest, want.ReleaseManifest) ||
		!bytes.Equal(got.ChannelSignatures[0], want.ChannelSignatures[0]) ||
		!bytes.Equal(got.ReleaseSignatures[0], want.ReleaseSignatures[0]) {
		t.Fatalf("round trip changed bytes: %#v", got)
	}
	got.ChannelManifest[0] ^= 1
	again, err := Parse(raw)
	if err != nil || bytes.Equal(got.ChannelManifest, again.ChannelManifest) {
		t.Fatal("Parse did not return fresh ownership")
	}
}

func TestBundleRejectsEveryAmbiguousOrUnboundedShape(t *testing.T) {
	base, err := Encode(testBundle())
	if err != nil {
		t.Fatal(err)
	}
	var paddedDocument encodedBundle
	if err := json.Unmarshal(base, &paddedDocument); err != nil { t.Fatal(err) }
	paddedDocument.ChannelManifest += "="
	padded, err := json.Marshal(paddedDocument)
	if err != nil { t.Fatal(err) }
	padded = append(padded, '\n')
	invalid := map[string][]byte{
		"empty": nil,
		"unknown field": bytes.Replace(base, []byte(`"schema":`), []byte(`"extra":true,"schema":`), 1),
		"duplicate field": bytes.Replace(base, []byte(`"schema":`), []byte(`"schema":"mesh-online-release-bundle-v1","schema":`), 1),
		"padded base64": padded,
		"whitespace": append([]byte(" "), base...),
		"trailing": append(append([]byte(nil), base...), []byte("{}")...),
		"oversize": bytes.Repeat([]byte{'x'}, MaxEncodedBundleSize+1),
	}
	for name, raw := range invalid {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(raw); err == nil {
				t.Fatal("invalid bundle accepted")
			}
		})
	}

	for _, role := range []string{"channel", "release"} {
		t.Run(role+" empty signatures", func(t *testing.T) {
			value := testBundle()
			if role == "channel" { value.ChannelSignatures = nil } else { value.ReleaseSignatures = nil }
			if _, err := Encode(value); err == nil { t.Fatal("empty signatures accepted") }
		})
	}

	value := testBundle()
	value.ChannelManifest = bytes.Repeat([]byte{'m'}, releasetrust.MaxManifestSize+1)
	if _, err := Encode(value); err == nil || !strings.Contains(err.Error(), "channel manifest") {
		t.Fatalf("oversized manifest error = %v", err)
	}
	value = testBundle()
	value.ReleaseSignatures = make([][]byte, releasetrust.MaxSignatureEnvelopes+1)
	for index := range value.ReleaseSignatures { value.ReleaseSignatures[index] = []byte{byte(index)} }
	if _, err := Encode(value); err == nil { t.Fatal("too many signatures accepted") }
	value = testBundle()
	value.ReleaseSignatures[0] = append([]byte(nil), value.ChannelSignatures[0]...)
	if _, err := Encode(value); err == nil { t.Fatal("cross-role collision accepted") }

	var encoded map[string]any
	if err := json.Unmarshal(base, &encoded); err != nil { t.Fatal(err) }
}
```

- [x] **Step 2: Run the package test and verify it fails to compile**

```bash
go test ./internal/onlinerelease -run TestBundle -count=1
```

Expected: failure because the package/types do not exist.

- [x] **Step 3: Implement the model and canonical codec**

Create `internal/onlinerelease/bundle.go` with these exact public types and
entry points:

```go
package onlinerelease

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	releasetrust "mesh/internal/release"
)

const (
	Schema               = "mesh-online-release-bundle-v1"
	MaxEncodedBundleSize = 6 << 20
)

type Bundle struct {
	ChannelManifest   []byte
	ChannelSignatures [][]byte
	ReleaseManifest   []byte
	ReleaseSignatures [][]byte
}

type encodedBundle struct {
	Schema               string   `json:"schema"`
	ChannelManifest      string   `json:"channel_manifest"`
	ChannelSignatures    []string `json:"channel_signatures"`
	ReleaseManifest      string   `json:"release_manifest"`
	ReleaseSignatures    []string `json:"release_signatures"`
}

func Encode(bundle Bundle) ([]byte, error) {
	document, err := encodeDocument(bundle)
	if err != nil { return nil, err }
	raw, err := json.Marshal(document)
	if err != nil { return nil, fmt.Errorf("encode online release bundle: %w", err) }
	raw = append(raw, '\n')
	if len(raw) > MaxEncodedBundleSize {
		return nil, fmt.Errorf("online release bundle exceeds %d bytes", MaxEncodedBundleSize)
	}
	return raw, nil
}

func Parse(raw []byte) (Bundle, error) {
	if len(raw) == 0 || len(raw) > MaxEncodedBundleSize {
		return Bundle{}, fmt.Errorf("online release bundle size must be between 1 and %d bytes", MaxEncodedBundleSize)
	}
	if err := releasetrust.ValidateStrictJSON(raw); err != nil {
		return Bundle{}, fmt.Errorf("invalid online release bundle JSON: %w", err)
	}
	var document encodedBundle
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return Bundle{}, fmt.Errorf("decode online release bundle: %w", err)
	}
	bundle, err := decodeDocument(document)
	if err != nil { return Bundle{}, err }
	canonical, err := Encode(bundle)
	if err != nil { return Bundle{}, err }
	if !bytes.Equal(raw, canonical) {
		return Bundle{}, errors.New("online release bundle must use canonical compact JSON followed by one LF")
	}
	return cloneBundle(bundle), nil
}
```

Implement private `encodeDocument`, `decodeDocument`, `decodeBytes`,
`validateBundle`, and `cloneBundle` helpers with these exact rules:

```go
func decodeBytes(value, role string, maximum int) ([]byte, error) {
	if value == "" { return nil, fmt.Errorf("%s is empty", role) }
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || base64.RawURLEncoding.EncodeToString(raw) != value {
		return nil, fmt.Errorf("%s must be canonical unpadded base64url", role)
	}
	if len(raw) == 0 || len(raw) > maximum {
		return nil, fmt.Errorf("%s size must be between 1 and %d bytes", role, maximum)
	}
	return raw, nil
}
```

`validateBundle` must require both manifests within
`release.MaxManifestSize`, both signature counts within 1 through
`release.MaxSignatureEnvelopes`, every envelope within
`release.MaxEnvelopeSize`, and reject byte-identical envelope SHA-256 values
across the complete two-role set. Keep the first raw value for each digest and
reject only when `bytes.Equal` also proves an exact collision. `cloneBundle`
must allocate every slice.

- [x] **Step 4: Run focused and full package tests**

```bash
gofmt -w internal/onlinerelease/bundle.go internal/onlinerelease/bundle_test.go
go test ./internal/onlinerelease ./internal/release -count=1
```

Expected: both packages report `ok`.

- [x] **Step 5: Commit the bundle schema checkpoint (skipped: workspace has no Git metadata)**

```bash
git add internal/onlinerelease internal/release
git commit -m "feat: add exact online release bundle schema"
```

## Task 3: Implement the canonical bundle URL

**Files:**
- Create: `internal/onlinerelease/url.go`
- Create: `internal/onlinerelease/url_test.go`

- [x] **Step 1: Write the accepted/rejected URL matrix**

Create tests that call `CanonicalBundleURL` for these exact cases:

```go
func TestCanonicalBundleURL(t *testing.T) {
	accepted := []string{
		"https://releases.example/channels/stable/bundle.json",
		"https://releases.example:8443/channels/stable/bundle.json",
		"https://127.0.0.1:18443/channels/stable/bundle.json",
		"https://[2001:db8::1]:8443/channels/stable/bundle.json",
	}
	for _, value := range accepted {
		if got, err := CanonicalBundleURL(value); err != nil || got != value {
			t.Fatalf("CanonicalBundleURL(%q) = %q, %v", value, got, err)
		}
	}
	rejected := []string{
		"", " http://releases.example/bundle.json", "http://releases.example/bundle.json",
		"https://user@releases.example/bundle.json", "https://releases.example/bundle.json#x",
		"https://releases.example/bundle.json?token=x", "https://RELEASES.example/bundle.json",
		"https://releases.example:443/bundle.json", "https://releases.example",
		"https://releases.example/a/../bundle.json", "https://releases.example//bundle.json",
		"https://releases.example/%62undle.json", "https://releases.example/bundle json",
	}
	for _, value := range rejected {
		if _, err := CanonicalBundleURL(value); err == nil {
			t.Fatalf("noncanonical URL accepted: %q", value)
		}
	}
}
```

- [x] **Step 2: Verify the test fails with an undefined function**

```bash
go test ./internal/onlinerelease -run TestCanonicalBundleURL -count=1
```

Expected: `undefined: CanonicalBundleURL`.

- [x] **Step 3: Implement exact normalization-by-rejection**

Create `internal/onlinerelease/url.go`:

```go
package onlinerelease

import (
	"errors"
	"net/url"
	"path"
	"strings"
)

func CanonicalBundleURL(raw string) (string, error) {
	if raw == "" || strings.TrimSpace(raw) != raw || strings.ContainsAny(raw, "\r\n\t") {
		return "", errors.New("bundle URL must not be empty or contain whitespace")
	}
	parsed, err := url.ParseRequestURI(raw)
	if err != nil || !parsed.IsAbs() || parsed.Scheme != "https" || parsed.Opaque != "" ||
		parsed.Host == "" || parsed.Hostname() == "" || parsed.User != nil || parsed.Fragment != "" ||
		parsed.RawQuery != "" || parsed.ForceQuery || parsed.RawPath != "" {
		return "", errors.New("bundle URL must be one absolute HTTPS URL without user information, query, or fragment")
	}
	if parsed.Path == "" || !strings.HasPrefix(parsed.Path, "/") || path.Clean(parsed.Path) != parsed.Path || strings.Contains(parsed.Path, "//") {
		return "", errors.New("bundle URL path must be nonempty and canonical")
	}
	if parsed.Port() == "443" || strings.ToLower(parsed.Host) != parsed.Host || parsed.String() != raw {
		return "", errors.New("bundle URL authority or encoding is not canonical")
	}
	return raw, nil
}
```

If Go's URI parser exposes an additional noncanonical accepted case, reject it
and add that exact input to the table; do not normalize and return a different
URL.

- [x] **Step 4: Run bundle and URL tests**

```bash
gofmt -w internal/onlinerelease/url.go internal/onlinerelease/url_test.go
go test ./internal/onlinerelease -count=1
```

Expected: `ok   mesh/internal/onlinerelease`.

- [x] **Step 5: Commit the URL checkpoint (skipped: workspace has no Git metadata)**

```bash
git add internal/onlinerelease/url.go internal/onlinerelease/url_test.go
git commit -m "feat: validate canonical online bundle URLs"
```

## Task 4: Add deterministic online-bundle release tooling

**Files:**
- Create: `cmd/mesh-release/assemble_online_bundle_linux.go`
- Create: `cmd/mesh-release/assemble_online_bundle_linux_test.go`
- Create: `cmd/mesh-release/assemble_online_bundle_other.go`
- Modify: `cmd/mesh-release/main.go`
- Modify: `cmd/mesh-release/main_test.go`

- [x] **Step 1: Write failing publisher workflow and race tests**

Use the existing `writeSnapshotAssemblyInputs` fixture from
`assemble_snapshot_linux_test.go` to create this central test:

```go
func TestAssembleOnlineBundleIsDeterministicCreateOnlyAndExact(t *testing.T) {
	inputs := writeSnapshotAssemblyInputs(t, filepath.Join(t.TempDir(), "inputs"))
	wantChannel, err := os.ReadFile(inputs.channelManifestPath)
	if err != nil { t.Fatal(err) }
	wantRelease, err := os.ReadFile(inputs.releaseManifestPath)
	if err != nil { t.Fatal(err) }
	first := filepath.Join(t.TempDir(), "bundle-one.json")
	second := filepath.Join(t.TempDir(), "bundle-two.json")
	options := onlineBundleAssemblyOptions{
		outputPath: first,
		channelManifestPath: inputs.channelManifestPath,
		channelSignaturePaths: reverseStrings(inputs.channelSignaturePaths),
		releaseManifestPath: inputs.releaseManifestPath,
		releaseSignaturePaths: reverseStrings(inputs.releaseSignaturePaths),
	}
	if err := assembleOnlineBundleUsing(options, onlineBundleAssemblyHooks{}); err != nil { t.Fatal(err) }
	options.outputPath = second
	options.channelSignaturePaths[0], options.channelSignaturePaths[1] = options.channelSignaturePaths[1], options.channelSignaturePaths[0]
	options.releaseSignaturePaths[0], options.releaseSignaturePaths[1] = options.releaseSignaturePaths[1], options.releaseSignaturePaths[0]
	if err := assembleOnlineBundleUsing(options, onlineBundleAssemblyHooks{}); err != nil { t.Fatal(err) }
	one, _ := os.ReadFile(first)
	two, _ := os.ReadFile(second)
	if !bytes.Equal(one, two) { t.Fatal("flag order changed online bundle bytes") }
	parsed, err := onlinerelease.Parse(one)
	if err != nil { t.Fatal(err) }
	if !bytes.Equal(parsed.ChannelManifest, wantChannel) || !bytes.Equal(parsed.ReleaseManifest, wantRelease) {
		t.Fatal("publisher changed exact manifest bytes")
	}
	if info, err := os.Stat(first); err != nil || info.Mode().Perm() != 0o644 { t.Fatalf("output mode = %v, %v", info, err) }
	if err := assembleOnlineBundleUsing(options, onlineBundleAssemblyHooks{}); err == nil { t.Fatal("overwrite accepted") }
}
```

Add separate tests patterned after `TestAssembleSnapshotRejects...` for symlink,
FIFO/directory, hard-link count, duplicate envelope bytes, input replacement,
in-place mutation through `afterInputRead`, output collision through
`beforePublish`, maximum envelope count, and cleanup of the exact staging file.

- [x] **Step 2: Run publisher tests and verify the command is missing**

```bash
go test ./cmd/mesh-release -run 'TestAssembleOnlineBundle' -count=1
```

Expected: build failures for `onlineBundleAssemblyOptions` and
`assembleOnlineBundleUsing`.

- [x] **Step 3: Implement Linux assembly using the existing stable-input helpers**

Define these concrete types/functions in
`cmd/mesh-release/assemble_online_bundle_linux.go`:

```go
//go:build linux

package main

type onlineBundleAssemblyOptions struct {
	outputPath            string
	channelManifestPath   string
	channelSignaturePaths []string
	releaseManifestPath   string
	releaseSignaturePaths []string
}

type onlineBundleAssemblyHooks struct {
	afterInputRead func(string)
	beforePublish  func()
}

func assembleOnlineBundle(args []string, output io.Writer) error
func assembleOnlineBundleUsing(options onlineBundleAssemblyOptions, hooks onlineBundleAssemblyHooks) error
```

`assembleOnlineBundle` uses the exact flags from the design. The implementation
must call `validateSnapshotAssemblyOptions` logic factored into a metadata-only
helper, build `snapshotInputSpec` values with existing limits, open all inputs
before reading any, call `readStableSnapshotInput`, invoke the mutation hook,
revalidate every descriptor, sort each signature role by SHA-256 with exact
bytes as the deterministic collision tie-breaker, reject all byte-identical
signature collisions, call `onlinerelease.Encode`, and publish a
mode-0644 create-only regular file using the existing `writeNewFile` plus an
exact readback/parse check.

Add this non-Linux behavior:

```go
//go:build !linux
package main

func assembleOnlineBundle([]string, io.Writer) error {
	return errors.New("assemble-online-bundle requires Linux stable-input and create-only publication semantics")
}
```

Wire `main.go` exactly:

```go
case "assemble-online-bundle":
	err = assembleOnlineBundle(os.Args[2:], os.Stdout)
```

and add the command to the usage string without changing existing command
names.

- [x] **Step 4: Run release tooling tests and non-Linux compile checks**

```bash
gofmt -w cmd/mesh-release/assemble_online_bundle_linux.go cmd/mesh-release/assemble_online_bundle_linux_test.go cmd/mesh-release/assemble_online_bundle_other.go cmd/mesh-release/main.go cmd/mesh-release/main_test.go
go test ./cmd/mesh-release -count=1
GOOS=darwin GOARCH=amd64 go test ./cmd/mesh-release -run '^$' -count=1
GOOS=windows GOARCH=amd64 go test ./cmd/mesh-release -run '^$' -count=1
```

Expected: all three commands succeed; the two cross-platform runs compile only.

Implementation note: on this Linux host, foreign-OS `go test` binaries cannot
execute and the two commands above reach `exec format error` after compiling.
The equivalent compile-only checks were run with `go test -c` for Darwin and
Windows, and both produced the expected foreign executable formats.

- [x] **Step 5: Commit the publisher checkpoint (skipped: workspace has no Git metadata)**

```bash
git add cmd/mesh-release
git commit -m "feat: assemble deterministic online release bundles"
```

## Task 5: Implement hardened metadata and artifact transport

**Files:**
- Create: `internal/onlinerelease/client.go`
- Create: `internal/onlinerelease/client_test.go`
- Modify: `internal/release/artifact.go`
- Modify: `internal/release/verify.go`
- Modify: `internal/release/release_test.go`

- [x] **Step 1: Write failing HTTP behavior tests**

Create a `roundTripFunc` fixture and tests that construct a client with
`newClientUsing(roundTripper, timeout)` and prove:

```go
func TestClientFetchesExactBundleAndArtifact(t *testing.T) {
	bundleRaw, err := Encode(testBundle())
	if err != nil { t.Fatal(err) }
	artifactRaw := []byte("authenticated artifact")
	digest := sha256.Sum256(artifactRaw)
	requests := 0
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		if request.Header.Get("Accept-Encoding") != "identity" || request.Header.Get("Authorization") != "" || request.Header.Get("Cookie") != "" {
			t.Fatalf("unsafe headers: %v", request.Header)
		}
		body := bundleRaw
		if requests == 2 { body = artifactRaw }
		return response(request, http.StatusOK, body, int64(len(body)), ""), nil
	})
	client := newClientUsing(transport, time.Second)
	bundle, err := client.FetchBundle(context.Background(), "https://releases.example/channels/stable/bundle.json")
	if err != nil { t.Fatal(err) }
	if !bytes.Equal(bundle.ChannelManifest, testBundle().ChannelManifest) { t.Fatal("bundle bytes changed") }
	file, err := os.CreateTemp(t.TempDir(), "artifact-")
	if err != nil { t.Fatal(err) }
	defer file.Close()
	want := releasetrust.Artifact{OS: runtime.GOOS, Arch: runtime.GOARCH, URL: "https://releases.example/artifact.tar", Size: int64(len(artifactRaw)), SHA256: hex.EncodeToString(digest[:])}
	if err := client.FetchArtifact(context.Background(), want, file); err != nil { t.Fatal(err) }
	if requests != 2 { t.Fatalf("requests = %d", requests) }
}
```

Add table cases for metadata/artifact status, redirect with `Location`, nil
body, compression, metadata body at `MaxEncodedBundleSize+1`, dishonest and
unknown metadata `Content-Length`, artifact missing/mismatched
`Content-Length`, truncation, overrun, wrong digest, read error, write error,
sync error, timeout, canceled context, and multiline header sanitization.

Add a production-client test that sets `HTTPS_PROXY` to a listener which fails
the test, calls a TLS server trusted through an injected transport/root pool,
and proves the proxy is never contacted. Assert `CheckRedirect` returns
`http.ErrUseLastResponse`, `Jar == nil`, compression/keepalive are disabled,
and TLS minimum is 1.2.

- [x] **Step 2: Run focused transport tests and verify missing symbols**

```bash
go test ./internal/onlinerelease -run 'TestClient|TestProductionClient' -count=1
```

Expected: build failure for `newClientUsing`, `FetchBundle`, and
`FetchArtifact`.

- [x] **Step 3: Implement the dedicated client**

Create these exact public boundaries in `client.go`:

```go
type Client struct { http *http.Client }

func NewClient() *Client { return &Client{http: newProductionHTTPClient()} }

func newClientUsing(transport http.RoundTripper, timeout time.Duration) *Client {
	return &Client{http: &http.Client{
		Transport: transport,
		Timeout: timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

func (client *Client) FetchBundle(ctx context.Context, address string) (Bundle, error)
func (client *Client) FetchArtifact(ctx context.Context, artifact releasetrust.Artifact, destination *os.File) error
```

`newProductionHTTPClient` must copy the hardened fields used by
`internal/nebulaartifact.newProductionClient`: `Proxy:nil`, bounded dial/TLS
header/total timeouts, TLS 1.2, no HTTP/2, keepalive, compression, cookies, or
redirects, one connection, bounded headers, and 32 KiB buffers. Both the
production client and the injected test client must enforce no redirects.

Both methods call a private `get(ctx,address,accept)` which sets only:

```go
request.Header.Set("Accept", accept)
request.Header.Set("Accept-Encoding", "identity")
request.Header.Set("Cache-Control", "no-cache")
request.Header.Set("User-Agent", "mesh-install/online-release-v1")
```

`FetchBundle` first calls `CanonicalBundleURL`, requires 200 and identity
encoding, rejects a declared size above the bound, reads with
`io.LimitReader(body, MaxEncodedBundleSize+1)`, rejects overflow, and calls
`Parse` on the exact bytes.

Add `release.ValidateArtifactReference(artifact Artifact) error` to
`internal/release/artifact.go`. It must enforce canonical platform identifiers,
size 1 through `MaxArtifactSize`, lowercase SHA-256, and the existing absolute
HTTPS URL rules. Refactor `parseReleaseManifest` to call that helper for every
artifact without changing its errors or selection behavior, and add focused
tests before using it from the online client.

`FetchArtifact` receives only a verifier-selected `release.Artifact`, calls
`release.ValidateArtifactReference`, requires status 200, identity encoding,
and exact `Content-Length`.
It streams through `io.LimitReader(size+1)` into `io.MultiWriter(destination,
sha256.New())`, compares exact length and digest, and calls `destination.Sync()`
only after both pass. It never truncates or seeks a caller-owned file.

- [x] **Step 4: Run tests including the race detector**

```bash
gofmt -w internal/onlinerelease/client.go internal/onlinerelease/client_test.go
go test ./internal/onlinerelease -count=1
go test -race ./internal/onlinerelease -count=1
```

Expected: both runs report `ok`.

- [x] **Step 5: Commit the transport checkpoint (skipped: workspace has no Git metadata)**

```bash
git add internal/onlinerelease internal/release
git commit -m "feat: download authenticated online release inputs"
```

## Task 6: Build root-private online intake and crash cleanup

**Files:**
- Create: `internal/linuxinstall/online_intake.go`
- Create: `internal/linuxinstall/online_intake_test.go`

- [x] **Step 1: Write failing intake ownership and cleanup tests**

Use a test-only root under `t.TempDir()` and require these concrete operations:

```go
func TestOnlineIntakeOwnsOnePrivateSnapshotAndCleansIt(t *testing.T) {
	rootPath := filepath.Join(t.TempDir(), "online-intake")
	lock, err := acquireOnlineIntake(rootPath, uint32(os.Geteuid()))
	if err != nil { t.Fatal(err) }
	defer lock.Close()
	workspace, err := lock.newWorkspace()
	if err != nil { t.Fatal(err) }
	info, _ := os.Stat(workspace.path)
	if !info.IsDir() || info.Mode().Perm() != 0o700 { t.Fatalf("workspace mode = %v", info.Mode()) }
	if err := workspace.writeFile("channel.json", []byte("channel"), 0o400); err != nil { t.Fatal(err) }
	if err := workspace.remove(); err != nil { t.Fatal(err) }
	if _, err := os.Stat(workspace.path); !errors.Is(err, os.ErrNotExist) { t.Fatalf("workspace survived: %v", err) }
}
```

Add tests for a second lock returning a stable contention error, recognized
`pending-<32 lowercase hex>` cleanup, unknown name refusal, symlink/FIFO/device
refusal, wrong owner/mode/link count, nested unknown entry, file size over the
role bound, replacement after inspection, mutated file during cleanup, parent
replacement, and cleanup fsync failure. Prove no test removes an unrecognized
sentinel.

- [x] **Step 2: Verify intake tests fail to compile**

```bash
go test ./internal/linuxinstall -run 'TestOnlineIntake' -count=1
```

Expected: undefined `acquireOnlineIntake`.

- [x] **Step 3: Implement the dedicated rooted namespace**

Define production constants and focused types:

```go
const (
	productionOnlineIntakeDirectory = "/var/lib/mesh-installer/online-intake"
	onlineIntakeLockName = "online.lock"
	onlineWorkspacePrefix = "pending-"
)

type onlineIntakeLock struct {
	root *os.Root
	dir  *os.File
	file *os.File
	uid  uint32
}

type onlineWorkspace struct {
	parent *onlineIntakeLock
	name   string
	path   string
	root   *os.Root
	info   os.FileInfo
}
```

Implement `ensureOnlineIntakeDirectory`, `acquireOnlineIntake`,
`(*onlineIntakeLock).reconcile`, `newWorkspace`, `writeFile`, `openArtifact`,
`sealArtifact`, `sync`, `remove`, and `Close` using the existing
`validatePrivateDirectory`, `rootInfoSys`, `syncRootDirectory`, random 16-byte
hex names, `O_NOFOLLOW`, `O_EXCL`, rooted descriptors, exact UID/mode/link
checks, and `flock(LOCK_EX|LOCK_NB)` patterns.

The reconciliation test names and implementation errors must distinguish
recognized crash-leftover cleanup from unknown-entry refusal.

Allowed workspace entries are exactly `channel.json`,
`channel-signature-NNN.json`, `release.json`,
`release-signature-NNN.json`, `mesh-linux-bundle.tar`, and `install.json` with
the bounds from the design. Reconciliation rejects the entire intake root if
any child or entry is unknown; it removes only fully validated recognized
children while holding the intake lock and synchronizes the parent.

- [x] **Step 4: Run intake and existing installer filesystem tests**

```bash
gofmt -w internal/linuxinstall/online_intake.go internal/linuxinstall/online_intake_test.go
go test ./internal/linuxinstall -run 'TestOnlineIntake|TestOpenMetadataSnapshot|TestCaptureArtifact' -count=1
go test -race ./internal/linuxinstall -run 'TestOnlineIntake' -count=1
```

Expected: both commands pass.

- [x] **Step 5: Commit the intake checkpoint (skipped: workspace has no Git metadata)**

```bash
git add internal/linuxinstall/online_intake.go internal/linuxinstall/online_intake_test.go
git commit -m "feat: add crash-safe online installer intake"
```

## Task 7: Materialize the existing offline snapshot from exact online bytes

**Files:**
- Modify: `internal/linuxinstall/online_intake.go`
- Modify: `internal/linuxinstall/online_intake_test.go`

- [x] **Step 1: Write the failing exact snapshot test**

Add a test that supplies an `onlinerelease.Bundle` with two signatures in
reverse digest order plus an already downloaded artifact file. Call:

```go
snapshotPath, err := workspace.materializeSnapshot(bundle, artifactFile)
```

Then call `OpenMetadataSnapshot(snapshotPath)` and assert every returned
manifest/signature byte equals the input, signatures are ordered by byte
SHA-256, the descriptor uses `mesh-linux-install-snapshot-v1`, directory mode
is 0700, every file is root/effective-user-owned mode 0400 with one link, and
the artifact identity matches the same inode written by the downloader.

Add failure cases for duplicate signature bytes, too many signatures, artifact
size change, replaced artifact descriptor, preexisting name, chmod/fsync error,
and source mutation during final readback.

- [x] **Step 2: Run the focused test and observe the missing method**

```bash
go test ./internal/linuxinstall -run 'TestOnlineWorkspaceMaterializeSnapshot' -count=1
```

Expected: `workspace.materializeSnapshot undefined`.

- [x] **Step 3: Implement deterministic snapshot materialization**

The method must:

```go
func (workspace *onlineWorkspace) materializeSnapshot(bundle onlinerelease.Bundle, artifact *os.File) (string, error)
```

Use these fixed basenames:

```go
const (
	onlineChannelManifestName = "channel.json"
	onlineReleaseManifestName = "release.json"
	onlineArtifactName = "mesh-linux-bundle.tar"
)
```

Sort fresh copies of each signature slice by SHA-256 and write
`channel-signature-%03d.json` and `release-signature-%03d.json`. Write exact
manifest/signature bytes mode 0400. Reopen the already synchronized artifact,
prove identity, chmod it from 0600 to 0400, and never copy it through an
unanchored pathname. Encode `InstallSnapshotDescriptor` with
`EncodeInstallSnapshotDescriptor`, write `install.json`, fsync all files and
the directory, then call `OpenMetadataSnapshot` and compare all exact bytes
before returning the absolute workspace path.

- [x] **Step 4: Run metadata/intake tests**

```bash
gofmt -w internal/linuxinstall/online_intake.go internal/linuxinstall/online_intake_test.go
go test ./internal/linuxinstall -run 'TestOnlineWorkspace|TestOpenMetadataSnapshot' -count=1
```

Expected: all selected tests pass.

- [x] **Step 5: Commit the snapshot bridge checkpoint (skipped: workspace has no Git metadata)**

```bash
git add internal/linuxinstall/online_intake.go internal/linuxinstall/online_intake_test.go
git commit -m "feat: bridge online bytes into offline snapshots"
```

## Task 8: Add two-pass online installer orchestration

**Files:**
- Create: `internal/linuxinstall/online.go`
- Create: `internal/linuxinstall/online_test.go`

- [x] **Step 1: Write failing orchestration-order tests**

Define fakes for `onlineReleaseFetcher` and `onlineInstallBoundary`. The primary
test records this exact trace:

```go
want := []string{
	"fetch-bundle", "lock-state", "verify-first", "unlock-state",
	"fetch-artifact", "materialize-snapshot", "apply-snapshot", "cleanup",
}
```

Assert `applyOnlineUsing` returns the injected `InstallResult`. Add tests that
prove:

- invalid first verification makes zero artifact requests;
- a pending state makes zero artifact requests;
- state-lock contention makes zero artifact requests;
- artifact failure never calls materialize/apply;
- final `ApplySnapshot` rejection returns no success result and cleans intake;
- a simulated state advance between verification passes reaches final apply
  and is rejected there;
- context cancellation reaches the fetcher and cleans intake;
- cleanup error joins the primary error without replacing it;
- online-intake contention does not touch state;
- exact same candidate is allowed to resume only through existing verifier
  semantics.

- [x] **Step 2: Run focused tests and verify orchestration is absent**

```bash
go test ./internal/linuxinstall -run 'TestApplyOnline' -count=1
```

Expected: undefined `applyOnlineUsing`.

- [x] **Step 3: Implement production and injected paths**

Create these interfaces and entry point:

```go
type onlineReleaseFetcher interface {
	FetchBundle(context.Context, string) (onlinerelease.Bundle, error)
	FetchArtifact(context.Context, releasetrust.Artifact, *os.File) error
}

type onlineInstallBoundary struct {
	stateDirectory string
	statePath      string
	intakeDirectory string
	verifyProduction func() error
	verifyCandidate func(SignedMetadata, *State) (CandidateMetadata, error)
	applySnapshot   func(context.Context, string) (InstallResult, error)
}

func ApplyOnline(ctx context.Context, bundleURL string) (InstallResult, error) {
	return applyOnlineUsing(ctx, bundleURL, onlinerelease.NewClient(), productionOnlineInstallBoundary())
}
```

`productionOnlineInstallBoundary` sets `verifyProduction` to a wrapper around
`verifyProductionBoundary`; tests inject a deterministic no-op or failure.
`applyOnlineUsing` validates the URL before filesystem changes, calls that
production check, ensures/acquires/reconciles intake, fetches metadata,
acquires `NewStateStore(boundary.statePath).AcquireLock()`, loads and validates
prior state/policy, rejects `Pending`, calls `verifyCandidate`, copies the
selected artifact value, closes the state lock, creates/open/syncs the artifact
file, fetches it, materializes the snapshot, and invokes `applySnapshot`.

Use named return values and `errors.Join` so workspace/intake close failures are
reported. Never pass the first `CandidateMetadata` into `ApplySnapshot`; only
its authenticated artifact value is used to bound the download.

Wrap failures with stable stage prefixes exactly matching the specification:
`validate bundle URL`, `fetch metadata`, `decode online bundle`,
`authenticate candidate before artifact`, `fetch artifact`, `materialize
offline snapshot`, `apply authenticated snapshot`, and `clean online intake`.
Tests must prove attacker-controlled multiline text is sanitized and no
success-shaped `InstallResult` is returned on any failing stage.

- [x] **Step 4: Run installer tests and race detector**

```bash
gofmt -w internal/linuxinstall/online.go internal/linuxinstall/online_test.go
go test ./internal/linuxinstall -count=1
go test -race ./internal/linuxinstall -run 'TestApplyOnline|TestOnlineIntake' -count=1
```

Expected: both runs pass.

- [x] **Step 5: Commit the online orchestration checkpoint (skipped: workspace has no Git metadata)**

```bash
git add internal/linuxinstall/online.go internal/linuxinstall/online_test.go
git commit -m "feat: apply online releases through offline installer"
```

## Task 9: Expose `mesh-install install-online`

**Files:**
- Modify: `cmd/mesh-install/main.go`
- Modify: `cmd/mesh-install/main_test.go`

- [x] **Step 1: Write failing CLI dispatch tests**

Refactor testability around a package variable, then add:

```go
func TestInstallOnlineDispatchesExactURLAndWritesExistingResult(t *testing.T) {
	original := applyOnline
	t.Cleanup(func() { applyOnline = original })
	wantURL := "https://releases.example/channels/stable/bundle.json"
	applyOnline = func(_ context.Context, got string) (linuxinstall.InstallResult, error) {
		if got != wantURL { t.Fatalf("URL = %q", got) }
		return linuxinstall.InstallResult{Operation: linuxinstall.OperationActivate, FirstInstall: true}, nil
	}
	var output bytes.Buffer
	if err := runContext(context.Background(), []string{"install-online", wantURL}, &output); err != nil { t.Fatal(err) }
	var got linuxinstall.InstallResult
	if err := json.Unmarshal(output.Bytes(), &got); err != nil { t.Fatal(err) }
	if got.Operation != linuxinstall.OperationActivate || !got.FirstInstall { t.Fatalf("result = %#v", got) }
}
```

Add `nil`, zero-URL, two-URL, and extra-flag cases to `TestUsage`. Prove an
injected error writes no success JSON.

- [x] **Step 2: Run CLI tests and observe usage rejection**

```bash
go test ./cmd/mesh-install -run 'TestInstallOnline|TestUsage' -count=1
```

Expected: `install-online` is rejected or `applyOnline` is undefined.

- [x] **Step 3: Wire the command without changing existing output**

Add:

```go
var applyOnline = linuxinstall.ApplyOnline
```

and this switch case before `install`:

```go
case "install-online":
	if len(args) != 2 { return usageError() }
	result, err := applyOnline(ctx, args[1])
	if err != nil { return err }
	return writeInstallResult(output, result)
```

Change usage exactly to:

```text
usage: mesh-install version | install-online EXACT_BUNDLE_URL | install ABSOLUTE_SNAPSHOT_DIR | recover | activate | rollback INSTALLED_ID
```

- [x] **Step 4: Run CLI and Linux installer checks**

```bash
gofmt -w cmd/mesh-install/main.go cmd/mesh-install/main_test.go
go test ./cmd/mesh-install ./internal/linuxinstall ./internal/onlinerelease -count=1
```

Expected: all Linux-only installer packages pass. Do not add non-Linux stubs:
`cmd/mesh-install` already deliberately imports the Linux-only installer
package and is not a native Darwin/Windows product.

- [x] **Step 5: Commit the CLI checkpoint (skipped: workspace has no Git metadata)**

```bash
git add cmd/mesh-install
git commit -m "feat: add mesh-install online command"
```

## Task 10: Add server URL configuration

**Files:**
- Modify: `cmd/mesh-server/storage_config.go`
- Modify: `cmd/mesh-server/storage_config_test.go`
- Modify: `cmd/mesh-server/main.go`
- Modify: `internal/httpapi/server.go`

- [x] **Step 1: Write failing server-config tests**

Extend `TestParseServerConfigStorageIsolation` or add a focused test:

```go
func TestParseServerConfigLinuxInstallBundleURL(t *testing.T) {
	want := "https://releases.example/channels/stable/bundle.json"
	config, err := parseServerConfig([]string{"--linux-install-bundle-url", want})
	if err != nil { t.Fatal(err) }
	if config.linuxInstallBundleURL != want { t.Fatalf("URL = %q", config.linuxInstallBundleURL) }
	for _, value := range []string{"http://releases.example/bundle.json", "https://releases.example/bundle.json?x=1", "https://RELEASES.example/bundle.json"} {
		if _, err := parseServerConfig([]string{"--linux-install-bundle-url", value}); err == nil {
			t.Fatalf("invalid URL accepted: %q", value)
		}
	}
}
```

Add an `httpapi.New` test proving a noncanonical `Options.LinuxInstallBundleURL`
is rejected even if a caller bypasses `parseServerConfig`.

- [x] **Step 2: Verify the config tests fail**

```bash
go test ./cmd/mesh-server ./internal/httpapi -run 'TestParseServerConfigLinuxInstallBundleURL|TestNewRejectsInvalidLinuxInstallBundleURL' -count=1
```

Expected: missing field errors.

- [x] **Step 3: Implement configuration and constructor parity**

Add `linuxInstallBundleURL string` to `serverConfig`, register:

```go
flags.StringVar(&config.linuxInstallBundleURL, "linux-install-bundle-url", "", "canonical public HTTPS URL for the signed Linux online release bundle")
```

After flag parsing, if nonempty call
`onlinerelease.CanonicalBundleURL` and require the returned string equals the
input. Add `LinuxInstallBundleURL string` to `httpapi.Options` and
`linuxInstallBundleURL string` to `Server`; repeat validation in `httpapi.New`.
Pass the field from `cmd/mesh-server/main.go` into `httpapi.Options`.

- [x] **Step 4: Run server configuration tests**

```bash
gofmt -w cmd/mesh-server/storage_config.go cmd/mesh-server/storage_config_test.go cmd/mesh-server/main.go internal/httpapi/server.go internal/httpapi/server_test.go
go test ./cmd/mesh-server ./internal/httpapi -count=1
```

Expected: both packages pass.

- [x] **Step 5: Commit the configuration checkpoint (skipped: workspace has no Git metadata)**

```bash
git add cmd/mesh-server internal/httpapi/server.go internal/httpapi/server_test.go
git commit -m "feat: configure informational Linux install URL"
```

## Task 11: Add the authenticated install-guide API

**Files:**
- Create: `internal/httpapi/install_guide.go`
- Create: `internal/httpapi/install_guide_test.go`
- Modify: `internal/httpapi/server.go`

- [x] **Step 1: Write failing authentication and exact-response tests**

Add a focused `newTestHTTPServerWithInstallURL` helper which mirrors
`newTestHTTPServerWithOptions` but sets `Options.LinuxInstallBundleURL`; do not
change the signatures of widely used existing helpers. Create one server with
no URL and one with the option set. Assert unauthenticated GET is 401. For authenticated
GET decode into `map[string]any` and compare exact objects:

```go
wantConfigured := map[string]any{
	"schema": "mesh-install-guide-v1",
	"linux": map[string]any{
		"online_available": true,
		"bundle_url": "https://releases.example/channels/stable/bundle.json",
	},
}
wantUnset := map[string]any{
	"schema": "mesh-install-guide-v1",
	"linux": map[string]any{"online_available": false},
}
```

Require `Content-Type: application/json`, `Cache-Control: no-store`, no extra
keys, and no control-store/audit mutation before/after each read.

- [x] **Step 2: Run focused API tests and verify 404**

```bash
go test ./internal/httpapi -run 'TestInstallGuide' -count=1
```

Expected: 404 or missing handler.

- [x] **Step 3: Implement the response and route**

Create:

```go
const installGuideSchema = "mesh-install-guide-v1"

type installGuideResponse struct {
	Schema string `json:"schema"`
	Linux linuxInstallGuide `json:"linux"`
}

type linuxInstallGuide struct {
	OnlineAvailable bool `json:"online_available"`
	BundleURL string `json:"bundle_url,omitempty"`
}

func (s *Server) installGuide(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, installGuideResponse{
		Schema: installGuideSchema,
		Linux: linuxInstallGuide{OnlineAvailable: s.linuxInstallBundleURL != "", BundleURL: s.linuxInstallBundleURL},
	})
}
```

Register exactly:

```go
mux.Handle("GET /api/v1/install-guide", s.admin(http.HandlerFunc(s.installGuide)))
```

next to the authenticated session/fleet read routes.

- [x] **Step 4: Run full HTTP API tests**

```bash
gofmt -w internal/httpapi/install_guide.go internal/httpapi/install_guide_test.go internal/httpapi/server.go
go test ./internal/httpapi -count=1
```

Expected: `ok   mesh/internal/httpapi`.

- [x] **Step 5: Commit the API checkpoint (skipped: workspace has no Git metadata)**

```bash
git add internal/httpapi/install_guide.go internal/httpapi/install_guide_test.go internal/httpapi/server.go
git commit -m "feat: expose authenticated install guide"
```

## Task 12: Add strict browser guide validation and command construction

**Files:**
- Create: `internal/httpapi/web/install-guide.js`
- Create: `internal/httpapi/webtest/install-guide.test.js`
- Modify: `internal/httpapi/web/index.html`

- [x] **Step 1: Write failing Node model tests**

Create tests for the exact configured and unavailable responses, then mutate
each required key/type/schema/URL. Include unknown keys, HTTP, query, fragment,
uppercase host, `:443`, dot segment, and a URL containing a single quote.

Assert command output exactly:

```js
const commands = guide.commands(
  'https://mesh.example',
  guide.validate({
    schema: guide.SCHEMA,
    linux: { online_available: true, bundle_url: 'https://releases.example/channels/stable/bundle.json' },
  }),
);
assert.equal(commands.install, "sudo ./mesh-install install-online 'https://releases.example/channels/stable/bundle.json'");
assert.match(commands.enroll, /--token-file -/);
assert.doesNotMatch(commands.enroll, /MESH_ENROLL_TOKEN=/);
assert.doesNotMatch(commands.enroll, /enrollment_token|Bearer/);
assert.equal(commands.activate, 'sudo /usr/local/bin/mesh-install activate');
```

Also assert `shellQuote("a'b") === "'a'\\''b'"` and that no raw token parameter
exists on `commands`.

- [x] **Step 2: Run Node test and verify the module is missing**

```bash
node --test internal/httpapi/webtest/install-guide.test.js
```

Expected: module-not-found failure.

- [x] **Step 3: Implement the standalone strict model**

Use the same UMD shape as `health.js`/`runtime-telemetry.js`:

```js
(function installGuideModule(root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  root.MeshInstallGuide = api;
}(typeof globalThis !== 'undefined' ? globalThis : this, function buildInstallGuide() {
  'use strict';
  const SCHEMA = 'mesh-install-guide-v1';
  // exactObject, canonicalURL, validate, shellQuote, and commands follow.
  return Object.freeze({ SCHEMA, validate, shellQuote, commands });
}));
```

`validate` permits exactly `schema` and `linux`; `linux` permits exactly
`online_available` plus `bundle_url` only when true. `canonicalURL` uses
`new URL`, requires `https:`, empty username/password/search/hash, a nonempty
pathname, lower-case authority, no explicit 443, no normalized difference, and
`parsed.href === raw` after accounting for the browser's trailing-slash rule
(which is rejected because the path must name a file).

`commands(origin, model)` returns a frozen object. The enrollment command must
use a non-exported `MESH_TOKEN_INPUT` shell variable, pipe it to
`meshctl enroll --token-file -`, capture `$?`, unset it, and end with
`test "$MESH_ENROLL_STATUS" -eq 0`; it must not use `sudo env`.

Load `install-guide.js` before `app.js` in `index.html`.

- [x] **Step 4: Run all browser model tests**

```bash
node --test internal/httpapi/webtest/install-guide.test.js internal/httpapi/webtest/health.test.js internal/httpapi/webtest/runtime-telemetry.test.js
```

Expected: all tests pass with zero failures.

- [x] **Step 5: Commit the browser model checkpoint (skipped: workspace has no Git metadata)**

```bash
git add internal/httpapi/web/install-guide.js internal/httpapi/webtest/install-guide.test.js internal/httpapi/web/index.html
git commit -m "feat: validate browser install guides"
```

## Task 13: Render the accurate three-step enrollment flow

**Files:**
- Modify: `internal/httpapi/web/index.html`
- Modify: `internal/httpapi/web/app.js`
- Modify: `internal/httpapi/web/style.css`
- Modify: `internal/httpapi/webtest/install-guide.test.js`

- [x] **Step 1: Add failing static and behavioral assertions**

Extend the Node test to read `index.html` and `app.js` from disk. Require IDs
`install-step`, `install-command`, `copy-install-command`, `enroll-command`,
`copy-enroll-command`, `activate-command`, and `copy-activate-command` exactly
once. Assert `app.js` requests `/api/v1/install-guide`, treats only 404 as the
old-server unavailable model, invokes `MeshInstallGuide.commands`, and contains
neither `sudo env MESH_ENROLL_TOKEN` nor
`systemctl enable --now mesh-agent.service`.

- [x] **Step 2: Run Node tests and observe missing markup/behavior**

```bash
node --test internal/httpapi/webtest/install-guide.test.js
```

Expected: assertion failure for missing install/activate controls.

- [x] **Step 3: Implement guide loading and DOM-safe rendering**

At app startup require `globalThis.MeshInstallGuide`. Add
`installGuide` to state with the validated unavailable model. In `showApp`, run:

```js
await Promise.all([loadInstallGuide(), loadNetworks()]);
```

Implement:

```js
async function loadInstallGuide() {
  try {
    state.installGuide = installGuideModel.validate(await api('/api/v1/install-guide'));
  } catch (error) {
    if (error.status !== 404) flash('Online installation guidance is temporarily unavailable.');
    state.installGuide = installGuideModel.validate({
      schema: installGuideModel.SCHEMA,
      linux: { online_available: false },
    });
  }
}
```

Replace the enrollment dialog's two old commands with three numbered sections.
`showEnrollment` calls `installGuideModel.commands(location.origin,
state.installGuide)`, assigns every value with `.textContent`, hides the copyable
online command when unavailable, shows the independent-bootstrap prerequisite,
and leaves the one-time token only in its existing `<details>` element.

Use one `copyText(button, element)` helper for all command buttons. Do not use
`innerHTML` or concatenate `result.enrollment_token` into any command.

Add restrained CSS for `.command-step`, `.command-step-number`, and unavailable
copy, preserving mobile layout, focus visibility, and existing colors.

- [x] **Step 4: Run browser and Go embed/API regressions**

```bash
node --test internal/httpapi/webtest/*.test.js
go test ./internal/httpapi -count=1
```

Expected: all Node and Go tests pass.

- [x] **Step 5: Commit the web-flow checkpoint (skipped: workspace has no Git metadata)**

```bash
git add internal/httpapi/web internal/httpapi/webtest
git commit -m "feat: guide node install enrollment and activation"
```

## Task 14: Document the online trust boundary and operator workflow

**Files:**
- Modify: `docs/release-trust.md`
- Modify: `packaging/systemd/README.md`

- [x] **Step 1: Add a failing documentation audit**

Run before editing:

```bash
rg -n 'mesh-online-release-bundle-v1|install-online|--linux-install-bundle-url' docs/release-trust.md packaging/systemd/README.md
```

Expected: no complete two-file operator workflow and a nonzero status.

- [x] **Step 2: Update the release and systemd guides**

Add the exact bundle command, artifact-first publication order, stable URL,
6 MiB transport bound, no-redirect transport, two-pass verification, private
intake/recovery semantics, `mesh-install install-online`, stdin enrollment, and
`mesh-install activate`. Retain the offline workflow as a fully supported
alternative.

Explicitly state that the bootstrap binary must still be authenticated
separately and that the online bundle/TLS/control plane cannot alter its
compiled policy.

- [x] **Step 3: Run documentation consistency searches**

```bash
rg -n 'mesh-online-release-bundle-v1|install-online|--linux-install-bundle-url|separately authenticated' docs/release-trust.md packaging/systemd/README.md
rg -n 'systemctl enable --now mesh-agent.service' internal/httpapi/web docs packaging/systemd
```

Expected: the first command finds all required surfaces; the second finds no
web onboarding instruction and only historical/contextual references if any.

- [x] **Step 4: Commit the operator-documentation checkpoint (skipped: workspace has no Git metadata)**

```bash
git add docs/release-trust.md packaging/systemd/README.md
git commit -m "docs: describe authenticated online installation"
```

## Task 15: Extend the real systemd install proof over HTTPS

**Files:**
- Modify: `packaging/systemd/proof-fedora42.Dockerfile`
- Modify: `scripts/linux-install-smoke.sh`
- Modify: `docs/security.md`
- Modify: `docs/roadmap.md`

- [x] **Step 1: Advance the proof fixture and generate a trusted TLS endpoint**

Change the Dockerfile label to `fedora42-v3` and install `python3`, `openssl`,
and `ca-certificates` in addition to existing packages. Change
`proof_image_identity` in the script to the same value and add `openssl` to
host prerequisites.

Generate a two-day test CA and a server certificate with SAN IP `127.0.0.1`
under the private smoke workspace. Copy the CA into
`/etc/pki/ca-trust/source/anchors/mesh-install-smoke-ca.crt`, run
`update-ca-trust`, and start a systemd-managed Python HTTPS file server on
`127.0.0.1:18443` rooted at `/root/mesh-proof/repository`. The Python helper
must disable redirects and emit exact `Content-Length` for files.

- [x] **Step 2: Publish real online bundles and negative fixtures**

Change release artifact/manifest URLs in `build_release` to the loopback HTTPS
repository. For each release run `mesh-release assemble-online-bundle`, copy
the artifact and bundle into immutable version paths, then copy the selected
bundle into `/channels/stable/bundle.json` only after the artifact exists.

Create bounded fixtures for: corrupt outer JSON, insufficient threshold,
expired/replayed channel, redirect, truncated artifact, oversized artifact,
wrong digest, and a response that blocks until a state-race semaphore is
released. Keep signing keys outside the served root.

- [x] **Step 3: Prove first online install and every no-mutation failure**

Replace the sequence-1 offline command with:

```bash
docker exec "${container_name}" /root/mesh-proof/bootstrap/mesh-install install-online \
  https://127.0.0.1:18443/channels/stable/bundle.json >"${work_dir}/install-one.json"
```

Before that success, invoke every negative metadata fixture and assert no
`state.json`, `/opt/mesh/current`, managed unit, enabled service, or runtime gate
appears (the private intake root may exist but must be empty). After first
install, rerun negative/replay fixtures and compare exact state SHA-256,
current-link target, unit digests, runtime gate, service enablement, active
state, and PIDs before/after.

Send SIGTERM during a blocked artifact response and assert normal cleanup.
Send SIGKILL during another blocked response, assert one recognized private
partial child, rerun a valid command, and assert reconciliation removes it.

- [x] **Step 4: Prove online upgrade, concurrent state rejection, rollback, recovery, and offline regression**

Use sequence 2 through `install-online` and retain all existing active-service,
process-provenance, high-water, rollback, and idempotency assertions.

For the state race, hold the online sequence-2 artifact response after first
verification, apply the same sequence through the offline snapshot, release the
response, and require online final verification to return an already-active
idempotent result only when exact bytes match. Repeat with a different signed
next sequence so the stale online candidate is rejected without changing the
newer high water.

Retain an explicit clean offline install in a fresh second container or after a
fully validated uninstall fixture to prove `mesh-install install` is unchanged.
Exercise an injected/controlled pending transaction and `mesh-install recover`
through the existing harness seam; do not synthesize invalid `state.json`
bytes.

- [x] **Step 5: Run syntax and live proof**

```bash
bash -n scripts/linux-install-smoke.sh
./scripts/linux-install-smoke.sh
```

Expected final line:

```text
PASS: authenticated HTTPS install, stopped first boot, stdin enrollment activation, online upgrade, state-race rejection, offline compatibility, rollback, recovery, cleanup, gates, units, state, and exact process provenance verified
```

- [x] **Step 6: Update security status and roadmap from fresh live evidence**

In `docs/security.md`, change only authenticated online retrieval from
outstanding to implemented and cite the just-completed systemd-container proof.
Keep native packaging, key rotation, bootstrap distribution, and installer
state compatibility outstanding.

In `docs/roadmap.md`, move “Authenticated online Mesh metadata/artifact
retrieval feeding the existing offline installer boundary” into implemented
evidence. Do not mark the enclosing milestone, bootstrap distribution, or
broader product goal complete.

- [x] **Step 7: Commit the live-proof checkpoint (skipped: workspace has no Git metadata)**

```bash
git add packaging/systemd/proof-fedora42.Dockerfile scripts/linux-install-smoke.sh docs/security.md docs/roadmap.md
git commit -m "test: prove authenticated online install end to end"
```

## Task 16: Run the complete verification and requirement audit

**Files:**
- Modify only files required to fix failures found by this audit.

- [x] **Step 1: Run formatting, unit, vet, race, browser, and shell checks**

```bash
gofmt -w internal/release/strictjson.go internal/release/artifact.go internal/release/verify.go internal/onlinerelease/*.go cmd/mesh-release/*.go cmd/mesh-install/*.go cmd/mesh-server/*.go internal/linuxinstall/*.go internal/httpapi/*.go
go test ./...
go vet ./...
go test -race -count=1 ./internal/onlinerelease ./internal/linuxinstall ./internal/httpapi
node --test internal/httpapi/webtest/*.test.js
bash -n scripts/*.sh
```

Expected: every command exits 0; record package/test counts from the fresh
output.

- [x] **Step 2: Run non-Linux compile checks**

```bash
set -Eeuo pipefail
for target in darwin/amd64 darwin/arm64 windows/amd64 windows/arm64; do
  target_os="${target%/*}"
  target_arch="${target#*/}"
  GOOS="${target_os}" GOARCH="${target_arch}" go test ./cmd/mesh-release ./internal/onlinerelease -run '^$' -count=1
  GOOS="${target_os}" GOARCH="${target_arch}" go test ./cmd/meshctl -run '^$' -count=1
done
```

Expected: all compile/build operations exit 0 without claiming native install
support.

- [x] **Step 3: Run security and privacy searches**

```bash
rg -n 'MESH_ENROLL_TOKEN=|sudo env|systemctl enable --now mesh-agent.service' internal/httpapi/web
rg -n -- '--(insecure|key|threshold|channel|clock|platform|proxy|ca-file)' cmd/mesh-install internal/linuxinstall/online.go
rg -n 'Authorization|Cookie|response body|private key|enrollment_token' internal/onlinerelease internal/httpapi/web/install-guide.js
rg -n 'http\.DefaultClient|ProxyFromEnvironment|CheckRedirect: nil' internal/onlinerelease
```

Expected: no forbidden runtime override, secret interpolation, default client,
proxy environment, redirect allowance, or response-body logging. Legitimate
test assertions/comments must be inspected rather than counted as failures.

- [x] **Step 4: Audit all eight specification acceptance criteria**

Create a temporary checklist outside the repository with one row per criterion
from
`docs/superpowers/specs/2026-07-20-authenticated-online-release-retrieval-design.md`.
For each row cite the exact test, smoke assertion, command output, API response,
or documentation line that proves it. Treat missing or indirect evidence as a
failure and implement the missing proof before continuing.

- [x] **Step 5: Audit temporary resources after all proofs**

```bash
test -z "$(find /tmp -maxdepth 1 -type d -name 'mesh-install-smoke.*' -print -quit)"
test -z "$(docker ps -a --filter 'name=^mesh-install-smoke-' --format '{{.Names}}')"
test -z "$(ps -eo comm=,args= | awk '$1 == "python3" && $0 ~ /18443/ { print } $1 == "mesh-install" && $0 ~ /install-online/ { print }')"
```

Expected: all commands exit 0 and print nothing.

- [x] **Step 6: Commit the final verified slice (skipped: workspace has no Git metadata)**

```bash
git add --all
git commit -m "feat: complete authenticated online release retrieval"
```

Do not create an empty commit. Do not mark the broader Mesh lifecycle goal
complete: bootstrap distribution, key rotation/revocation, native packages,
installer-state compatibility, and remaining end-to-end product work still
remain.
