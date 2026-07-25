package origindeploy

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"mesh/internal/originimage"
	"mesh/internal/releaseorigin"
)

const (
	testManifest   = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	testGeneration = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	testContainer  = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	testLocalImage = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
)

var runtimeTestTime = time.Date(2026, 7, 21, 22, 0, 0, 123456789, time.UTC)

type testFixture struct {
	config       Config
	image        string
	composePath  string
	securityPath string
	runner       *fakeRunner
	generation   releaseorigin.GenerationReceipt
	inspectCalls int
	socket       net.Listener
}

type fakeRunner struct {
	containerRaw []byte
	imageRaw     []byte
	dockerPath   string
	socketPath   string
	containerID  string
	imageID      string
}

func (runner *fakeRunner) InspectContainer(_ context.Context, dockerPath, socketPath, containerID string) ([]byte, error) {
	runner.dockerPath, runner.socketPath, runner.containerID = dockerPath, socketPath, containerID
	return runner.containerRaw, nil
}

func (runner *fakeRunner) InspectImage(_ context.Context, dockerPath, socketPath, imageID string) ([]byte, error) {
	runner.dockerPath, runner.socketPath, runner.imageID = dockerPath, socketPath, imageID
	return runner.imageRaw, nil
}

func TestVerifyBindsImageComposeGenerationAndRuntime(t *testing.T) {
	fixture := newTestFixture(t)
	receipt, err := Verify(context.Background(), fixture.config, func() time.Time { return runtimeTestTime }, fixture.runner, fixture.inspect)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Schema != ReceiptSchema || receipt.Image != fixture.image || receipt.ManifestSHA256 != testManifest ||
		receipt.Generation != testGeneration || receipt.ContainerID != testContainer || receipt.LocalImageID != testLocalImage ||
		receipt.PublicURL != "https://releases.example.com:8444" || receipt.RuntimeUser != "1000:1000" ||
		receipt.VerifiedAt != runtimeTestTime.Format(time.RFC3339Nano) || !validDigest(receipt.ImageReceiptSHA256) ||
		!validDigest(receipt.SecurityReceiptSHA256) ||
		!validDigest(receipt.ComposeSHA256) || !validDigest(receipt.DockerSHA256) {
		t.Fatalf("unexpected runtime receipt: %#v", receipt)
	}
	if fixture.inspectCalls != 2 || fixture.runner.dockerPath != fixture.config.DockerPath ||
		fixture.runner.socketPath != fixture.config.DockerSocket || fixture.runner.containerID != testContainer ||
		fixture.runner.imageID != testLocalImage {
		t.Fatalf("unexpected inspection calls: fixture=%#v runner=%#v", fixture.inspectCalls, fixture.runner)
	}
	raw, err := EncodeReceipt(receipt)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseReceipt(raw)
	if err != nil || parsed != receipt {
		t.Fatalf("receipt round trip = %#v, %v", parsed, err)
	}
	outputPath := filepath.Join(t.TempDir(), "runtime.json")
	if err := WriteNewReceipt(outputPath, raw); err != nil {
		t.Fatal(err)
	}
	if stored, err := os.ReadFile(outputPath); err != nil || !bytes.Equal(stored, raw) {
		t.Fatalf("stored receipt = %q, %v", stored, err)
	}
	if err := WriteNewReceipt(outputPath, raw); err == nil {
		t.Fatal("runtime receipt replacement accepted")
	}
}

func TestVerifyRejectsComposeAndRuntimeDrift(t *testing.T) {
	for name, mutate := range map[string]func(*testFixture){
		"compose build": func(fixture *testFixture) {
			mutateJSONFile(t, fixture.composePath, func(document map[string]any) {
				service(document)["build"] = map[string]any{"context": "."}
			})
		},
		"extra service": func(fixture *testFixture) {
			mutateJSONFile(t, fixture.composePath, func(document map[string]any) {
				document["services"].(map[string]any)["other"] = map[string]any{"image": fixture.image}
			})
		},
		"compose image": func(fixture *testFixture) {
			mutateJSONFile(t, fixture.composePath, func(document map[string]any) {
				service(document)["image"] = "registry.example.com/mesh/origin@sha256:" + strings.Repeat("f", 64)
			})
		},
		"compose mount": func(fixture *testFixture) {
			mutateJSONFile(t, fixture.composePath, func(document map[string]any) {
				service(document)["volumes"].([]any)[0].(map[string]any)["source"] = "/wrong/repository"
			})
		},
		"unhealthy": func(fixture *testFixture) {
			fixture.runner.containerRaw = mutateJSON(fixture.runner.containerRaw, func(record map[string]any) {
				record["State"].(map[string]any)["Health"].(map[string]any)["Status"] = "unhealthy"
			})
		},
		"writable root": func(fixture *testFixture) {
			fixture.runner.containerRaw = mutateJSON(fixture.runner.containerRaw, func(record map[string]any) {
				record["HostConfig"].(map[string]any)["ReadonlyRootfs"] = false
			})
		},
		"runtime mount": func(fixture *testFixture) {
			fixture.runner.containerRaw = mutateJSON(fixture.runner.containerRaw, func(record map[string]any) {
				record["Mounts"].([]any)[0].(map[string]any)["Source"] = "/wrong/repository"
			})
		},
		"repo digest": func(fixture *testFixture) {
			fixture.runner.imageRaw = mutateJSON(fixture.runner.imageRaw, func(record map[string]any) {
				record["RepoDigests"] = []any{"registry.example.com/mesh/origin@sha256:" + strings.Repeat("f", 64)}
			})
		},
		"security image": func(fixture *testFixture) {
			mutateSecurityReceipt(t, fixture.securityPath, func(receipt *originSecurityReceipt) {
				receipt.Image.DockerImageID = "sha256:" + strings.Repeat("f", 64)
			})
		},
		"generation changes": func(fixture *testFixture) {
			fixture.inspectCalls = -100
		},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newTestFixture(t)
			mutate(fixture)
			inspector := fixture.inspect
			if fixture.inspectCalls == -100 {
				fixture.inspectCalls = 0
				inspector = func(_ string) (releaseorigin.GenerationReceipt, error) {
					fixture.inspectCalls++
					receipt := fixture.generation
					if fixture.inspectCalls == 2 {
						receipt.TotalSize++
					}
					return receipt, nil
				}
			}
			if receipt, err := Verify(context.Background(), fixture.config, func() time.Time { return runtimeTestTime }, fixture.runner, inspector); err == nil || receipt != (Receipt{}) {
				t.Fatalf("drift verification = %#v, %v", receipt, err)
			}
		})
	}
}

func TestVerifyRejectsLinkedInputsAndAmbiguousIdentity(t *testing.T) {
	fixture := newTestFixture(t)
	linkedCompose := filepath.Join(t.TempDir(), "compose.json")
	if err := os.Symlink(fixture.composePath, linkedCompose); err != nil {
		t.Fatal(err)
	}
	fixture.config.ComposeConfig = linkedCompose
	if _, err := Verify(context.Background(), fixture.config, func() time.Time { return runtimeTestTime }, fixture.runner, fixture.inspect); err == nil {
		t.Fatal("linked Compose evidence accepted")
	}

	fixture = newTestFixture(t)
	linkedSecurity := filepath.Join(t.TempDir(), "security.json")
	if err := os.Symlink(fixture.securityPath, linkedSecurity); err != nil {
		t.Fatal(err)
	}
	fixture.config.SecurityReceipt = linkedSecurity
	if _, err := Verify(context.Background(), fixture.config, func() time.Time { return runtimeTestTime }, fixture.runner, fixture.inspect); err == nil {
		t.Fatal("linked image-security evidence accepted")
	}

	fixture = newTestFixture(t)
	fixture.config.ContainerID = "short"
	if _, err := Verify(context.Background(), fixture.config, func() time.Time { return runtimeTestTime }, fixture.runner, fixture.inspect); err == nil {
		t.Fatal("ambiguous container ID accepted")
	}

	fixture = newTestFixture(t)
	fixture.runner.containerRaw = append(fixture.runner.containerRaw, []byte("{}")...)
	if _, err := Verify(context.Background(), fixture.config, func() time.Time { return runtimeTestTime }, fixture.runner, fixture.inspect); err == nil {
		t.Fatal("ambiguous Docker JSON accepted")
	}
}

func TestOriginSecurityReceiptRejectsPolicyAndCanonicalDrift(t *testing.T) {
	valid := exactSecurityReceipt(t, testLocalImage)
	for name, mutate := range map[string]func([]byte) []byte{
		"missing LF": func(raw []byte) []byte { return bytes.TrimSuffix(raw, []byte{'\n'}) },
		"duplicate field": func(raw []byte) []byte {
			return bytes.Replace(raw, []byte(`{"image":`), []byte(`{"schema":"mesh-origin-image-security-receipt-v1","image":`), 1)
		},
		"unknown field": func(raw []byte) []byte {
			var document map[string]any
			_ = json.Unmarshal(raw, &document)
			document["unexpected"] = true
			result, _ := json.Marshal(document)
			return append(result, '\n')
		},
		"high vulnerability": func(raw []byte) []byte {
			var receipt originSecurityReceipt
			_ = json.Unmarshal(raw, &receipt)
			receipt.VulnerabilityScan.MatchCount = 1
			receipt.VulnerabilityScan.CountsBySeverity = map[string]int{"High": 1}
			result, _ := json.Marshal(receipt)
			return append(result, '\n')
		},
		"nonempty secret report": func(raw []byte) []byte {
			var receipt originSecurityReceipt
			_ = json.Unmarshal(raw, &receipt)
			receipt.SecretScan.RootfsReport = securityDigestRecord{SHA256: strings.Repeat("9", 64), Size: 4}
			result, _ := json.Marshal(receipt)
			return append(result, '\n')
		},
		"scanner boundary": func(raw []byte) []byte {
			var receipt originSecurityReceipt
			_ = json.Unmarshal(raw, &receipt)
			receipt.ScannerBoundary.ImageArchiveAndScan = "privileged"
			result, _ := json.Marshal(receipt)
			return append(result, '\n')
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseOriginSecurityReceipt(mutate(bytes.Clone(valid))); err == nil {
				t.Fatal("security receipt drift accepted")
			}
		})
	}
}

func newTestFixture(t *testing.T) *testFixture {
	t.Helper()
	root := t.TempDir()
	generationPath := filepath.Join(root, testGeneration)
	if err := os.Mkdir(generationPath, 0o755); err != nil {
		t.Fatal(err)
	}
	image := "registry.example.com/mesh/origin@sha256:" + testManifest
	imageReceiptRaw, err := originimage.EncodeReceipt(originimage.Receipt{
		Schema: originimage.ReceiptSchema, Image: image, ManifestSHA256: testManifest,
		PublicKeySHA256: strings.Repeat("a", 64), CosignSHA256: strings.Repeat("b", 64),
		VerifiedAt: "2026-07-21T21:00:00Z", SignatureCount: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	imageReceiptPath := filepath.Join(root, "image-receipt.json")
	if err := os.WriteFile(imageReceiptPath, imageReceiptRaw, 0o644); err != nil {
		t.Fatal(err)
	}
	securityReceiptPath := filepath.Join(root, "security-receipt.json")
	securityReceiptRaw := exactSecurityReceipt(t, testLocalImage)
	if err := os.WriteFile(securityReceiptPath, securityReceiptRaw, 0o644); err != nil {
		t.Fatal(err)
	}
	composeRaw := exactComposeJSON(t, image, generationPath, root)
	composePath := filepath.Join(root, "compose.json")
	if err := os.WriteFile(composePath, composeRaw, 0o644); err != nil {
		t.Fatal(err)
	}
	dockerPath := filepath.Join(root, "docker")
	if err := os.WriteFile(dockerPath, []byte("docker fixture\n"), 0o555); err != nil {
		t.Fatal(err)
	}
	socketPath := filepath.Join(root, "docker.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	selection, err := parseCompose(composeRaw, image, generationPath)
	if err != nil {
		t.Fatal(err)
	}
	containerRaw, imageRaw := exactDockerJSON(t, selection)
	fixture := &testFixture{
		image: image, composePath: composePath, securityPath: securityReceiptPath, socket: listener,
		config: Config{ImageReceipt: imageReceiptPath, SecurityReceipt: securityReceiptPath, ComposeConfig: composePath, Generation: generationPath,
			ContainerID: testContainer, DockerPath: dockerPath, DockerSocket: socketPath, Timeout: time.Minute},
		runner: &fakeRunner{containerRaw: containerRaw, imageRaw: imageRaw},
		generation: releaseorigin.GenerationReceipt{Schema: releaseorigin.GenerationSchema, Generation: testGeneration,
			IndexSHA256: testGeneration, ObjectCount: 2, TotalSize: 123},
	}
	return fixture
}

func exactSecurityReceipt(t *testing.T, localImageID string) []byte {
	t.Helper()
	record := func(character string, size int64) securityDigestRecord {
		return securityDigestRecord{SHA256: strings.Repeat(character, 64), Size: size}
	}
	var receipt originSecurityReceipt
	receipt.Schema = originSecurityReceiptSchema
	receipt.VerifiedAt = "2026-07-21T21:30:00Z"
	receipt.Image.Schema = originArchiveEvidenceSchema
	receipt.Image.Platform = "linux/amd64"
	receipt.Image.DockerImageID = "sha256:" + localImageID
	receipt.Image.ConfigDigest = strings.Repeat("e", 64)
	receipt.Image.FilesystemEntryCount = 18
	receipt.Image.Archive = record("1", 2<<20)
	receipt.Image.Files = map[string]securityDigestRecord{
		"etc/ssl/certs/ca-certificates.crt": record("2", 128<<10),
		"run/origin/index.json":             {SHA256: emptyFileSHA256, Size: 0},
		"run/tls/ca.crt":                    {SHA256: emptyFileSHA256, Size: 0},
		"run/tls/server.crt":                {SHA256: emptyFileSHA256, Size: 0},
		"run/tls/server.key":                {SHA256: emptyFileSHA256, Size: 0},
		"usr/local/bin/mesh-healthcheck":    record("3", 2<<20),
		"usr/local/bin/mesh-origin":         record("4", 2<<20),
	}
	receipt.SBOM.SyftVersion = "1.44.0"
	receipt.SBOM.SyftSchema = "16.1.3"
	receipt.SBOM.SyftPackageCount = 5
	receipt.SBOM.SyftJSON = record("5", 1024)
	receipt.SBOM.SPDXVersion = "SPDX-2.3"
	receipt.SBOM.SPDXPackageCount = 6
	receipt.SBOM.SPDXJSON = record("6", 1024)
	receipt.ScannerBoundary.DatabaseUpdate = "networked scanner with only an empty private database cache mounted"
	receipt.ScannerBoundary.ImageArchiveAndScan = "networkless, read-only, non-root, capability-free containers without a Docker socket"
	receipt.SecretScan.GitleaksVersion = "v8.30.1"
	receipt.SecretScan.Policy = "default rules over exact origin rootfs text and both binaries' strings; only the exact public oauth2 v0.36.0 Go checksum is allowlisted"
	receipt.SecretScan.RootfsReport = securityDigestRecord{SHA256: emptyGitleaksSHA256, Size: 3}
	receipt.SecretScan.BinaryStringsReport = securityDigestRecord{SHA256: emptyGitleaksSHA256, Size: 3}
	receipt.VulnerabilityScan.GrypeVersion = "0.112.0"
	receipt.VulnerabilityScan.DatabaseSchema = "v6.1.9"
	receipt.VulnerabilityScan.DatabaseBuilt = "2026-07-21T07:05:18Z"
	receipt.VulnerabilityScan.DatabaseStatus = record("7", 1024)
	receipt.VulnerabilityScan.Policy = "reject High or Critical matches and every match with a published fix"
	receipt.VulnerabilityScan.Report = record("8", 1024)
	receipt.VulnerabilityScan.CountsBySeverity = map[string]int{}
	receipt.VulnerabilityScan.RemainingNonfixedIDs = []string{}
	raw, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	return append(raw, '\n')
}

func mutateSecurityReceipt(t *testing.T, path string, mutate func(*originSecurityReceipt)) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := parseOriginSecurityReceipt(raw)
	if err != nil {
		t.Fatal(err)
	}
	mutate(&receipt)
	raw, err = json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(raw, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

func (fixture *testFixture) inspect(_ string) (releaseorigin.GenerationReceipt, error) {
	fixture.inspectCalls++
	return fixture.generation, nil
}

func exactComposeJSON(t *testing.T, image, generationPath, root string) []byte {
	t.Helper()
	volumes := []any{
		composeVolumeMap(filepath.Join(generationPath, "repository"), "/srv/repository"),
		composeVolumeMap(filepath.Join(generationPath, "origin-index.json"), "/run/origin/index.json"),
		composeVolumeMap(filepath.Join(root, "server.crt"), "/run/tls/server.crt"),
		composeVolumeMap(filepath.Join(root, "server.key"), "/run/tls/server.key"),
		composeVolumeMap(filepath.Join(root, "ca.crt"), "/run/tls/ca.crt"),
	}
	document := map[string]any{"name": "mesh-origin", "services": map[string]any{"origin": map[string]any{
		"image": image, "user": "1000:1000", "init": true, "read_only": true,
		"restart": "unless-stopped", "stop_grace_period": "15s", "cap_drop": []any{"ALL"},
		"security_opt": []any{"no-new-privileges:true"}, "pids_limit": 64, "mem_limit": "134217728",
		"command":     []any{"--listen=0.0.0.0:8444", "--public-url=https://releases.example.com:8444", "--tls-cert=/run/tls/server.crt", "--tls-key=/run/tls/server.key", "--root=/srv/repository", "--index=/run/origin/index.json"},
		"environment": map[string]any{"MESH_HEALTHCHECK_CA_FILE": "/run/tls/ca.crt", "MESH_HEALTHCHECK_SERVER_NAME": "releases.example.com", "MESH_HEALTHCHECK_URL": "https://127.0.0.1:8444/readyz"},
		"healthcheck": map[string]any{"test": []any{"CMD", "/usr/local/bin/mesh-healthcheck"}, "timeout": "4s", "interval": "10s", "retries": 6, "start_period": "10s"},
		"logging":     map[string]any{"driver": "local", "options": map[string]any{"max-file": "5", "max-size": "10m"}},
		"ports":       []any{map[string]any{"mode": "ingress", "host_ip": "127.0.0.1", "target": 8444, "published": "8444", "protocol": "tcp"}},
		"volumes":     volumes,
	}}}
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return append(raw, '\n')
}

func composeVolumeMap(source, target string) map[string]any {
	return map[string]any{"type": "bind", "source": source, "target": target, "read_only": true, "bind": map[string]any{"create_host_path": false}}
}

func exactDockerJSON(t *testing.T, selection composeSelection) ([]byte, []byte) {
	t.Helper()
	mounts := make([]any, 0, len(selection.volumes))
	for _, target := range []string{"/srv/repository", "/run/origin/index.json", "/run/tls/server.crt", "/run/tls/server.key", "/run/tls/ca.crt"} {
		mounts = append(mounts, map[string]any{"Type": "bind", "Source": selection.volumes[target], "Destination": target, "RW": false})
	}
	container := map[string]any{
		"Id": testContainer, "Image": "sha256:" + testLocalImage,
		"State":      map[string]any{"Running": true, "Paused": false, "Restarting": false, "Dead": false, "Health": map[string]any{"Status": "healthy"}},
		"Config":     map[string]any{"Image": selection.image.canonical, "User": selection.user, "Cmd": selection.command},
		"HostConfig": map[string]any{"ReadonlyRootfs": true, "CapDrop": []any{"ALL"}, "SecurityOpt": []any{"no-new-privileges:true"}, "PidsLimit": 64, "Memory": 128 * 1024 * 1024, "Privileged": false, "Init": true},
		"Mounts":     mounts,
	}
	image := map[string]any{"Id": "sha256:" + testLocalImage, "RepoDigests": []any{selection.image.canonical}, "Architecture": "amd64", "Os": "linux"}
	containerRaw, _ := json.Marshal([]any{container})
	imageRaw, _ := json.Marshal([]any{image})
	return containerRaw, imageRaw
}

func mutateJSONFile(t *testing.T, path string, mutate func(map[string]any)) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	mutate(document)
	raw, _ = json.Marshal(document)
	if err := os.WriteFile(path, append(raw, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

func mutateJSON(raw []byte, mutate func(map[string]any)) []byte {
	var records []map[string]any
	_ = json.Unmarshal(raw, &records)
	mutate(records[0])
	result, _ := json.Marshal(records)
	return result
}

func service(document map[string]any) map[string]any {
	return document["services"].(map[string]any)["origin"].(map[string]any)
}
