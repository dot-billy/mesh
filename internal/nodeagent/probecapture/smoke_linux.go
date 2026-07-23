//go:build linux

// Command probecapture is a Linux-only privileged smoke helper. It is not
// shipped by Mesh; the overlay harness builds it into a private temporary
// directory to count exact TUN echo requests and bridge one pre-opened host
// control-plane connection into a network namespace.
package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"mesh/internal/control"
	"mesh/internal/nodeagent"
)

const maximumCaptureDuration = 30 * time.Second
const maximumCaptureTargets = 8

type repeatedStrings []string

func (values *repeatedStrings) String() string { return strings.Join(*values, ",") }

func (values *repeatedStrings) Set(value string) error {
	*values = append(*values, value)
	return nil
}

func main() {
	if len(os.Args) < 2 {
		fatal(errors.New("usage: probecapture <check|capture|proxy>"))
	}
	var err error
	switch os.Args[1] {
	case "check":
		err = checkCapture()
	case "capture":
		err = capture(os.Args[2:])
	case "proxy":
		err = proxy(os.Args[2:])
	case "telemetry":
		err = telemetry(os.Args[2:])
	case "config-failure":
		err = configFailure(os.Args[2:])
	case "runtime-stopped":
		err = runtimeStopped(os.Args[2:])
	default:
		err = errors.New("unknown probecapture command")
	}
	if err != nil {
		fatal(err)
	}
}

func configFailure(arguments []string) error {
	flags := flag.NewFlagSet("config-failure", flag.ContinueOnError)
	statePath := flags.String("state", "", "private agent state path")
	revision := flags.Int64("revision", 0, "attempted signed config revision")
	digest := flags.String("digest", "", "attempted signed config SHA-256")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return errors.New("invalid config-failure arguments")
	}
	if *statePath == "" || !filepath.IsAbs(*statePath) || filepath.Clean(*statePath) != *statePath || *revision < 1 || len(*digest) != 64 {
		return errors.New("config-failure requires an absolute clean state path and exact revision/digest")
	}
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return fmt.Errorf("read process capability status: %w", err)
	}
	if err := requireEmptyCapabilities(status); err != nil {
		return err
	}
	store, err := nodeagent.NewStateStore(*statePath)
	if err != nil {
		return fmt.Errorf("open agent state: %w", err)
	}
	agent := &nodeagent.Agent{
		Store: store, HTTPClient: &http.Client{Timeout: 30 * time.Second},
		Reloader: nodeagent.ReloadFunc(func(context.Context) error { return nil }), AgentVersion: "config-failure-smoke",
	}
	defer agent.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := agent.ReportConfigApplyFailure(ctx, control.ConfigApplyFailureInput{
		AttemptedConfigRevision: *revision, AttemptedConfigSHA256: *digest,
		FailureCode: control.ConfigApplyFailureCodeActivation,
	}); err != nil {
		return fmt.Errorf("post config activation failure: %w", err)
	}
	return json.NewEncoder(os.Stdout).Encode(struct {
		Revision int64  `json:"attempted_config_revision"`
		Digest   string `json:"attempted_config_sha256"`
	}{Revision: *revision, Digest: *digest})
}

type telemetryConfiguration struct {
	statePath        string
	nebulaBinary     string
	nebulaCertBinary string
}

func parseTelemetryArguments(arguments []string) (telemetryConfiguration, error) {
	flags := flag.NewFlagSet("telemetry", flag.ContinueOnError)
	statePath := flags.String("state", "", "private agent state path")
	nebulaBinary := flags.String("nebula", "", "absolute Nebula binary path")
	nebulaCertBinary := flags.String("nebula-cert", "", "absolute nebula-cert binary path")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return telemetryConfiguration{}, errors.New("invalid telemetry arguments")
	}
	for _, path := range []string{*statePath, *nebulaBinary, *nebulaCertBinary} {
		if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return telemetryConfiguration{}, errors.New("telemetry paths must be absolute and clean")
		}
	}
	return telemetryConfiguration{
		statePath: *statePath, nebulaBinary: *nebulaBinary, nebulaCertBinary: *nebulaCertBinary,
	}, nil
}

func telemetry(arguments []string) error {
	configuration, err := parseTelemetryArguments(arguments)
	if err != nil {
		return err
	}
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return fmt.Errorf("read process capability status: %w", err)
	}
	if err := requireEmptyCapabilities(status); err != nil {
		return err
	}
	store, err := nodeagent.NewStateStore(configuration.statePath)
	if err != nil {
		return fmt.Errorf("open agent state: %w", err)
	}
	agent := &nodeagent.Agent{
		Store: store, HTTPClient: &http.Client{Timeout: 30 * time.Second},
		Validator: nodeagent.BundleValidator{
			NebulaBinary: configuration.nebulaBinary, NebulaCertBinary: configuration.nebulaCertBinary,
			Runner: nodeagent.ExecCommandRunner{},
		},
		Reloader:     nodeagent.ReloadFunc(func(context.Context) error { return nil }),
		AgentVersion: "active-probe-smoke",
	}
	defer agent.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	sequence, err := agent.Heartbeat(ctx, nodeagent.Health{
		NebulaVersion: "1.10.3", NebulaRunning: true, Status: "healthy",
	})
	if err != nil {
		return fmt.Errorf("post lifecycle heartbeat: %w", err)
	}
	if err := agent.ReportRuntimeTelemetry(ctx, sequence); err != nil {
		return fmt.Errorf("post runtime telemetry: %w", err)
	}
	return json.NewEncoder(os.Stdout).Encode(struct {
		HeartbeatSequence int64 `json:"heartbeat_sequence"`
	}{HeartbeatSequence: sequence})
}

func runtimeStopped(arguments []string) error {
	configuration, err := parseTelemetryArguments(arguments)
	if err != nil {
		return err
	}
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return fmt.Errorf("read process capability status: %w", err)
	}
	if err := requireEmptyCapabilities(status); err != nil {
		return err
	}
	store, err := nodeagent.NewStateStore(configuration.statePath)
	if err != nil {
		return fmt.Errorf("open agent state: %w", err)
	}
	agent := &nodeagent.Agent{
		Store: store, HTTPClient: &http.Client{Timeout: 30 * time.Second},
		Validator: nodeagent.BundleValidator{
			NebulaBinary: configuration.nebulaBinary, NebulaCertBinary: configuration.nebulaCertBinary,
			Runner: nodeagent.ExecCommandRunner{},
		},
		Reloader: nodeagent.ReloadFunc(func(context.Context) error { return nil }), AgentVersion: "runtime-stopped-smoke",
	}
	defer agent.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	sequence, err := agent.Heartbeat(ctx, nodeagent.Health{
		NebulaVersion: "1.10.3", NebulaRunning: false, Status: "degraded",
		LastError: "smoke-injected managed runtime stopped evidence",
	})
	if err != nil {
		return fmt.Errorf("post stopped-runtime heartbeat: %w", err)
	}
	return json.NewEncoder(os.Stdout).Encode(struct {
		HeartbeatSequence int64 `json:"heartbeat_sequence"`
	}{HeartbeatSequence: sequence})
}

func requireEmptyCapabilities(status []byte) error {
	counts := map[string]int{"CapEff:": 0, "CapBnd:": 0}
	for _, line := range strings.Split(string(status), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		if _, tracked := counts[fields[0]]; !tracked {
			continue
		}
		counts[fields[0]]++
		if len(fields[1]) != 16 {
			return errors.New("process capability status is malformed")
		}
		value, err := strconv.ParseUint(fields[1], 16, 64)
		if err != nil || value != 0 {
			return errors.New("telemetry smoke process must have empty effective and bounding capabilities")
		}
	}
	if counts["CapEff:"] != 1 || counts["CapBnd:"] != 1 {
		return errors.New("process capability status is incomplete or duplicated")
	}
	return nil
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "probecapture: %v\n", err)
	os.Exit(1)
}

func exactEchoRequest(packet []byte, source, target netip.Addr) bool {
	if len(packet) < 28 || !source.Is4() || !target.Is4() || packet[0]>>4 != 4 {
		return false
	}
	headerBytes := int(packet[0]&0x0f) * 4
	if headerBytes < 20 || headerBytes+8 > len(packet) {
		return false
	}
	totalBytes := int(binary.BigEndian.Uint16(packet[2:4]))
	if totalBytes < headerBytes+8 || totalBytes > len(packet) || packet[9] != 1 || binary.BigEndian.Uint16(packet[6:8])&0x3fff != 0 {
		return false
	}
	sourceBytes := source.As4()
	targetBytes := target.As4()
	for index := 0; index < 4; index++ {
		if packet[12+index] != sourceBytes[index] || packet[16+index] != targetBytes[index] {
			return false
		}
	}
	return packet[headerBytes] == 8 && packet[headerBytes+1] == 0
}

func checkCapture() error {
	fileDescriptor, err := openCaptureSocket("lo")
	if err != nil {
		return err
	}
	return unix.Close(fileDescriptor)
}

func parseCaptureTargets(source netip.Addr, raw []string) ([]netip.Addr, error) {
	if !source.Is4() || len(raw) < 1 || len(raw) > maximumCaptureTargets {
		return nil, errors.New("invalid capture source or target count")
	}
	targets := make([]netip.Addr, 0, len(raw))
	seen := make(map[netip.Addr]struct{}, len(raw))
	for _, value := range raw {
		target, err := netip.ParseAddr(value)
		if err != nil || !target.Is4() || target == source {
			return nil, errors.New("invalid capture target")
		}
		if _, duplicate := seen[target]; duplicate {
			return nil, errors.New("duplicate capture target")
		}
		seen[target] = struct{}{}
		targets = append(targets, target)
	}
	return targets, nil
}

func capture(arguments []string) error {
	flags := flag.NewFlagSet("capture", flag.ContinueOnError)
	interfaceName := flags.String("interface", "", "TUN interface")
	sourceRaw := flags.String("source", "", "source overlay IPv4")
	var targetRaw repeatedStrings
	flags.Var(&targetRaw, "target", "target overlay IPv4 (repeat for a bounded set)")
	duration := flags.Duration("duration", 8*time.Second, "bounded capture duration")
	readyFile := flags.String("ready-file", "", "private readiness file")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return errors.New("invalid capture arguments")
	}
	source, sourceErr := netip.ParseAddr(*sourceRaw)
	targets, targetErr := parseCaptureTargets(source, targetRaw)
	if sourceErr != nil || targetErr != nil || *duration <= 0 || *duration > maximumCaptureDuration {
		return errors.New("invalid capture addresses or duration")
	}
	if err := validateReadyPath(*readyFile); err != nil {
		return err
	}
	fileDescriptor, err := openCaptureSocket(*interfaceName)
	if err != nil {
		return err
	}
	defer unix.Close(fileDescriptor)
	if err := os.WriteFile(*readyFile, []byte("ready\n"), 0o600); err != nil {
		return fmt.Errorf("write capture readiness: %w", err)
	}
	deadline := time.Now().Add(*duration)
	buffer := make([]byte, 65535)
	requests := 0
	for time.Now().Before(deadline) {
		remaining := time.Until(deadline)
		pollFor := min(remaining, 100*time.Millisecond)
		timeoutMS := int((pollFor + time.Millisecond - 1) / time.Millisecond)
		poll := []unix.PollFd{{Fd: int32(fileDescriptor), Events: unix.POLLIN}}
		ready, err := unix.Poll(poll, timeoutMS)
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if err != nil {
			return fmt.Errorf("poll capture socket: %w", err)
		}
		if ready == 0 {
			continue
		}
		count, _, err := unix.Recvfrom(fileDescriptor, buffer, 0)
		if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EINTR) {
			continue
		}
		if err != nil {
			return fmt.Errorf("receive captured packet: %w", err)
		}
		for _, target := range targets {
			if exactEchoRequest(buffer[:count], source, target) {
				requests++
				break
			}
		}
	}
	return json.NewEncoder(os.Stdout).Encode(struct {
		EchoRequests int `json:"echo_requests"`
	}{EchoRequests: requests})
}

func openCaptureSocket(interfaceName string) (int, error) {
	if len(interfaceName) < 1 || len(interfaceName) > 15 {
		return -1, errors.New("invalid capture interface")
	}
	networkInterface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return -1, fmt.Errorf("resolve capture interface: %w", err)
	}
	// TUN is an ARPHRD_NONE device rather than Ethernet. Subscribe to the
	// interface's cooked packet stream with ETH_P_ALL and apply the exact IPv4
	// ICMP allowlist in userspace; an ETH_P_IP packet-socket subscription can
	// miss locally originated TUN frames before link-protocol demultiplexing.
	protocol := htons(unix.ETH_P_ALL)
	fileDescriptor, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, int(protocol))
	if err != nil {
		return -1, fmt.Errorf("open capture socket: %w", err)
	}
	if err := unix.Bind(fileDescriptor, &unix.SockaddrLinklayer{Protocol: protocol, Ifindex: networkInterface.Index}); err != nil {
		unix.Close(fileDescriptor)
		return -1, fmt.Errorf("bind capture socket: %w", err)
	}
	return fileDescriptor, nil
}

func htons(value uint16) uint16 { return value<<8 | value>>8 }

func proxy(arguments []string) error {
	flags := flag.NewFlagSet("proxy", flag.ContinueOnError)
	listenRaw := flags.String("listen", "", "loopback listen address")
	backendFD := flags.Int("backend-fd", -1, "pre-opened host connection")
	readyFile := flags.String("ready-file", "", "private readiness file")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || *backendFD < 3 {
		return errors.New("invalid proxy arguments")
	}
	host, portRaw, err := net.SplitHostPort(*listenRaw)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		return errors.New("proxy must listen on a numeric loopback address")
	}
	port, err := strconv.Atoi(portRaw)
	if err != nil || port < 1024 || port > 65535 {
		return errors.New("invalid proxy port")
	}
	if err := validateReadyPath(*readyFile); err != nil {
		return err
	}
	backendFile := os.NewFile(uintptr(*backendFD), "mesh-smoke-backend")
	if backendFile == nil {
		return errors.New("backend file descriptor is unavailable")
	}
	defer backendFile.Close()
	backend, err := net.FileConn(backendFile)
	if err != nil {
		return fmt.Errorf("adopt backend connection: %w", err)
	}
	defer backend.Close()
	listener, err := net.Listen("tcp4", *listenRaw)
	if err != nil {
		return fmt.Errorf("listen for namespace control proxy: %w", err)
	}
	defer listener.Close()
	if err := os.WriteFile(*readyFile, []byte("ready\n"), 0o600); err != nil {
		return fmt.Errorf("write proxy readiness: %w", err)
	}
	frontend, err := listener.Accept()
	if err != nil {
		return fmt.Errorf("accept namespace control connection: %w", err)
	}
	defer frontend.Close()
	var wait sync.WaitGroup
	wait.Add(2)
	go func() {
		defer wait.Done()
		_, _ = io.Copy(backend, frontend)
		if connection, ok := backend.(*net.TCPConn); ok {
			_ = connection.CloseWrite()
		}
	}()
	go func() {
		defer wait.Done()
		_, _ = io.Copy(frontend, backend)
		if connection, ok := frontend.(*net.TCPConn); ok {
			_ = connection.CloseWrite()
		}
	}()
	wait.Wait()
	return nil
}

func validateReadyPath(path string) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Base(path) == "." {
		return errors.New("readiness path must be an absolute clean file path")
	}
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil || !parent.IsDir() || parent.Mode()&os.ModeSymlink != 0 || parent.Mode().Perm()&0o077 != 0 {
		return errors.New("readiness parent must be a private real directory")
	}
	if _, err := os.Lstat(path); err == nil || !errors.Is(err, os.ErrNotExist) {
		return errors.New("readiness file must not already exist")
	}
	return nil
}
