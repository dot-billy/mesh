package origindeploy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"mesh/internal/originimage"
)

const maxComposeConfig = 1 << 20

type imageReference struct {
	canonical string
	digest    string
}

func parseImage(value string) (imageReference, error) {
	parsed, err := originimage.ParseReference(value)
	if err != nil {
		return imageReference{}, err
	}
	return imageReference{canonical: parsed.Canonical, digest: parsed.Digest}, nil
}

type composeSelection struct {
	image     imageReference
	user      string
	command   []string
	publicURL string
	volumes   map[string]string
}

type composeDocument struct {
	Services map[string]json.RawMessage `json:"services"`
}

type composeService struct {
	Image           string            `json:"image"`
	User            string            `json:"user"`
	Init            bool              `json:"init"`
	ReadOnly        bool              `json:"read_only"`
	Restart         string            `json:"restart"`
	StopGracePeriod string            `json:"stop_grace_period"`
	CapDrop         []string          `json:"cap_drop"`
	SecurityOpt     []string          `json:"security_opt"`
	PidsLimit       int64             `json:"pids_limit"`
	MemLimit        string            `json:"mem_limit"`
	Command         []string          `json:"command"`
	Environment     map[string]string `json:"environment"`
	Volumes         []composeVolume   `json:"volumes"`
	Ports           []composePort     `json:"ports"`
	Healthcheck     composeHealth     `json:"healthcheck"`
	Logging         composeLogging    `json:"logging"`
}

type composeVolume struct {
	Type     string `json:"type"`
	Source   string `json:"source"`
	Target   string `json:"target"`
	ReadOnly bool   `json:"read_only"`
	Bind     struct {
		CreateHostPath bool `json:"create_host_path"`
	} `json:"bind"`
}

type composePort struct {
	Mode      string `json:"mode"`
	HostIP    string `json:"host_ip"`
	Target    int    `json:"target"`
	Published string `json:"published"`
	Protocol  string `json:"protocol"`
}

type composeHealth struct {
	Test        []string `json:"test"`
	Timeout     string   `json:"timeout"`
	Interval    string   `json:"interval"`
	Retries     int      `json:"retries"`
	StartPeriod string   `json:"start_period"`
}

type composeLogging struct {
	Driver  string            `json:"driver"`
	Options map[string]string `json:"options"`
}

func parseCompose(raw []byte, expectedImage string, generationPath string) (composeSelection, error) {
	if len(raw) == 0 || len(raw) > maxComposeConfig {
		return composeSelection{}, fmt.Errorf("rendered production Compose size must be between 1 and %d bytes", maxComposeConfig)
	}
	if err := validateStrictJSON(raw); err != nil {
		return composeSelection{}, fmt.Errorf("invalid rendered production Compose JSON: %w", err)
	}
	var document composeDocument
	if err := json.Unmarshal(raw, &document); err != nil || len(document.Services) != 1 {
		return composeSelection{}, errors.New("rendered production Compose must contain exactly one service")
	}
	originRaw, ok := document.Services["origin"]
	if !ok {
		return composeSelection{}, errors.New("rendered production Compose must contain only the origin service")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(originRaw, &fields); err != nil {
		return composeSelection{}, errors.New("rendered production origin service is invalid")
	}
	if _, exists := fields["build"]; exists {
		return composeSelection{}, errors.New("rendered production origin service must not contain a build")
	}
	var service composeService
	if err := json.Unmarshal(originRaw, &service); err != nil {
		return composeSelection{}, errors.New("rendered production origin service is invalid")
	}
	image, err := parseImage(service.Image)
	if err != nil || image.canonical != expectedImage {
		return composeSelection{}, errors.New("rendered production image does not match the authenticated image receipt")
	}
	if _, _, err := parseRuntimeUser(service.User); err != nil {
		return composeSelection{}, err
	}
	if !service.Init || !service.ReadOnly || service.Restart != "unless-stopped" || service.StopGracePeriod != "15s" ||
		!slices.Equal(service.CapDrop, []string{"ALL"}) || !slices.Equal(service.SecurityOpt, []string{"no-new-privileges:true"}) ||
		service.PidsLimit != 64 || service.MemLimit != "134217728" {
		return composeSelection{}, errors.New("rendered production origin hardening or resource contract drifted")
	}
	publicURL, err := exactOriginCommand(service.Command)
	if err != nil {
		return composeSelection{}, err
	}
	parsedURL, _ := parsePublicURL(publicURL)
	wantEnvironment := map[string]string{
		"MESH_HEALTHCHECK_CA_FILE":     "/run/tls/ca.crt",
		"MESH_HEALTHCHECK_SERVER_NAME": parsedURL.Hostname(),
		"MESH_HEALTHCHECK_URL":         "https://127.0.0.1:8444/readyz",
	}
	if !mapsEqual(service.Environment, wantEnvironment) {
		return composeSelection{}, errors.New("rendered production origin health environment drifted")
	}
	if !slices.Equal(service.Healthcheck.Test, []string{"CMD", "/usr/local/bin/mesh-healthcheck"}) ||
		service.Healthcheck.Timeout != "4s" || service.Healthcheck.Interval != "10s" ||
		service.Healthcheck.Retries != 6 || service.Healthcheck.StartPeriod != "10s" {
		return composeSelection{}, errors.New("rendered production origin healthcheck drifted")
	}
	if service.Logging.Driver != "local" || !mapsEqual(service.Logging.Options, map[string]string{"max-file": "5", "max-size": "10m"}) {
		return composeSelection{}, errors.New("rendered production origin logging contract drifted")
	}
	if len(service.Ports) != 1 || service.Ports[0].Mode != "ingress" || service.Ports[0].Target != 8444 ||
		service.Ports[0].Protocol != "tcp" || net.ParseIP(service.Ports[0].HostIP) == nil {
		return composeSelection{}, errors.New("rendered production origin port contract drifted")
	}
	published, err := strconv.Atoi(service.Ports[0].Published)
	if err != nil || published < 1 || published > 65535 {
		return composeSelection{}, errors.New("rendered production origin published port is invalid")
	}
	volumes, err := exactComposeVolumes(service.Volumes, generationPath)
	if err != nil {
		return composeSelection{}, err
	}
	return composeSelection{image: image, user: service.User, command: service.Command, publicURL: publicURL, volumes: volumes}, nil
}

func exactOriginCommand(command []string) (string, error) {
	if len(command) != 6 || command[0] != "--listen=0.0.0.0:8444" ||
		!strings.HasPrefix(command[1], "--public-url=") || command[2] != "--tls-cert=/run/tls/server.crt" ||
		command[3] != "--tls-key=/run/tls/server.key" || command[4] != "--root=/srv/repository" ||
		command[5] != "--index=/run/origin/index.json" {
		return "", errors.New("rendered production origin command drifted")
	}
	publicURL := strings.TrimPrefix(command[1], "--public-url=")
	if _, err := parsePublicURL(publicURL); err != nil {
		return "", err
	}
	return publicURL, nil
}

func parsePublicURL(value string) (*url.URL, error) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.Hostname() == "" || parsed.User != nil ||
		parsed.Path != "" || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.String() != value {
		return nil, errors.New("origin public URL must be one canonical HTTPS origin without credentials, path, query, or fragment")
	}
	if port := parsed.Port(); port != "" {
		number, err := strconv.Atoi(port)
		if err != nil || number < 1 || number > 65535 {
			return nil, errors.New("origin public URL port is invalid")
		}
	}
	return parsed, nil
}

func parseRuntimeUser(value string) (uint64, uint64, error) {
	parts := strings.Split(value, ":")
	if len(parts) != 2 {
		return 0, 0, errors.New("origin runtime user must be one explicit non-root numeric UID:GID")
	}
	uid, uidErr := strconv.ParseUint(parts[0], 10, 32)
	gid, gidErr := strconv.ParseUint(parts[1], 10, 32)
	if uidErr != nil || gidErr != nil || uid == 0 || gid == 0 || strconv.FormatUint(uid, 10) != parts[0] || strconv.FormatUint(gid, 10) != parts[1] {
		return 0, 0, errors.New("origin runtime user must be one explicit non-root canonical numeric UID:GID")
	}
	return uid, gid, nil
}

func exactComposeVolumes(volumes []composeVolume, generationPath string) (map[string]string, error) {
	if len(volumes) != 5 {
		return nil, errors.New("rendered production origin must contain exactly five bind mounts")
	}
	wantGeneration := map[string]string{
		"/srv/repository":        filepath.Join(generationPath, "repository"),
		"/run/origin/index.json": filepath.Join(generationPath, "origin-index.json"),
	}
	result := make(map[string]string, len(volumes))
	for _, volume := range volumes {
		if volume.Type != "bind" || !volume.ReadOnly || volume.Bind.CreateHostPath || volume.Target == "" || volume.Source == "" {
			return nil, errors.New("rendered production origin mount hardening drifted")
		}
		if _, duplicate := result[volume.Target]; duplicate {
			return nil, errors.New("rendered production origin contains duplicate mount targets")
		}
		if !filepath.IsAbs(volume.Source) || filepath.Clean(volume.Source) != volume.Source {
			return nil, errors.New("rendered production origin mount source must be clean and absolute")
		}
		result[volume.Target] = volume.Source
	}
	for target, source := range wantGeneration {
		if result[target] != source {
			return nil, errors.New("rendered production origin generation mounts do not match the inspected generation")
		}
	}
	for _, target := range []string{"/run/tls/server.crt", "/run/tls/server.key", "/run/tls/ca.crt"} {
		if result[target] == "" {
			return nil, errors.New("rendered production origin TLS mount is missing")
		}
	}
	return result, nil
}

func mapsEqual(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if right[key] != value {
			return false
		}
	}
	return true
}

type containerInspect struct {
	ID    string `json:"Id"`
	Image string `json:"Image"`
	State struct {
		Running    bool `json:"Running"`
		Paused     bool `json:"Paused"`
		Restarting bool `json:"Restarting"`
		Dead       bool `json:"Dead"`
		Health     *struct {
			Status string `json:"Status"`
		} `json:"Health"`
	} `json:"State"`
	Config struct {
		Image string   `json:"Image"`
		User  string   `json:"User"`
		Cmd   []string `json:"Cmd"`
	} `json:"Config"`
	HostConfig struct {
		ReadonlyRootfs bool     `json:"ReadonlyRootfs"`
		CapDrop        []string `json:"CapDrop"`
		SecurityOpt    []string `json:"SecurityOpt"`
		PidsLimit      int64    `json:"PidsLimit"`
		Memory         int64    `json:"Memory"`
		Privileged     bool     `json:"Privileged"`
		Init           *bool    `json:"Init"`
	} `json:"HostConfig"`
	Mounts []struct {
		Type        string `json:"Type"`
		Source      string `json:"Source"`
		Destination string `json:"Destination"`
		RW          bool   `json:"RW"`
	} `json:"Mounts"`
}

type imageInspect struct {
	ID           string   `json:"Id"`
	RepoDigests  []string `json:"RepoDigests"`
	Architecture string   `json:"Architecture"`
	OS           string   `json:"Os"`
}

func decodeOne[T any](raw []byte, label string) (T, error) {
	var zero T
	if len(raw) == 0 || len(raw) > 2<<20 || validateStrictJSON(raw) != nil {
		return zero, fmt.Errorf("Docker returned invalid or ambiguous %s JSON", label)
	}
	var records []T
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(&records); err != nil || len(records) != 1 {
		return zero, fmt.Errorf("Docker must return exactly one %s record", label)
	}
	return records[0], nil
}

func validateContainer(record containerInspect, requestedID string, selection composeSelection) (string, error) {
	if record.ID != requestedID || !strings.HasPrefix(record.Image, "sha256:") || !validDigest(strings.TrimPrefix(record.Image, "sha256:")) {
		return "", errors.New("running origin container identity is inconsistent")
	}
	if !record.State.Running || record.State.Paused || record.State.Restarting || record.State.Dead ||
		record.State.Health == nil || record.State.Health.Status != "healthy" {
		return "", errors.New("origin container is not exactly running and healthy")
	}
	if record.Config.Image != selection.image.canonical || record.Config.User != selection.user || !slices.Equal(record.Config.Cmd, selection.command) {
		return "", errors.New("origin container image, user, or command differs from production Compose")
	}
	if !record.HostConfig.ReadonlyRootfs || record.HostConfig.Privileged || record.HostConfig.Init == nil || !*record.HostConfig.Init ||
		!slices.Equal(record.HostConfig.CapDrop, []string{"ALL"}) || !slices.Equal(record.HostConfig.SecurityOpt, []string{"no-new-privileges:true"}) ||
		record.HostConfig.PidsLimit != 64 || record.HostConfig.Memory != 128*1024*1024 {
		return "", errors.New("origin container runtime hardening differs from production Compose")
	}
	if len(record.Mounts) != len(selection.volumes) {
		return "", errors.New("origin container mount set differs from production Compose")
	}
	seen := make(map[string]bool, len(record.Mounts))
	for _, mount := range record.Mounts {
		if mount.Type != "bind" || mount.RW || selection.volumes[mount.Destination] != mount.Source || seen[mount.Destination] {
			return "", errors.New("origin container mount differs from production Compose")
		}
		seen[mount.Destination] = true
	}
	return strings.TrimPrefix(record.Image, "sha256:"), nil
}

func validateImage(record imageInspect, localID, exactReference string) error {
	if record.ID != "sha256:"+localID || record.OS != "linux" || (record.Architecture != "amd64" && record.Architecture != "arm64") {
		return errors.New("local origin image identity or platform is inconsistent")
	}
	if !slices.Contains(record.RepoDigests, exactReference) {
		return errors.New("local origin image does not retain the authenticated repository digest")
	}
	return nil
}
