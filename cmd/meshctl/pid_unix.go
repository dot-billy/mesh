//go:build !windows

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type pidRuntime struct {
	path         string
	nebulaBinary string
}

func newPIDRuntime(path, nebulaBinary string) (runtimeController, error) {
	resolved, err := exec.LookPath(nebulaBinary)
	if err != nil {
		return nil, fmt.Errorf("resolve Nebula binary for PID validation: %w", err)
	}
	resolved, err = filepath.Abs(resolved)
	if err != nil {
		return nil, fmt.Errorf("resolve Nebula binary path: %w", err)
	}
	return &pidRuntime{path: path, nebulaBinary: filepath.Clean(resolved)}, nil
}

func (r *pidRuntime) Reload(ctx context.Context) error {
	process, err := r.process(ctx)
	if err != nil {
		return err
	}
	if err := process.Signal(syscall.SIGHUP); err != nil {
		return fmt.Errorf("signal Nebula process: %w", err)
	}
	return nil
}

func (r *pidRuntime) Observe(ctx context.Context) (runtimeObservation, error) {
	process, err := r.process(ctx)
	if err != nil {
		return runtimeObservation{}, err
	}
	if err := process.Signal(syscall.Signal(0)); err != nil {
		return runtimeObservation{}, fmt.Errorf("Nebula process is not running: %w", err)
	}
	return runtimeObservation{
		HeartbeatAllowed: false, NebulaRunning: true, Status: "degraded",
		LastError: "SIGHUP delivery and process liveness cannot prove the running Nebula instance applied the active bundle",
	}, nil
}

func (r *pidRuntime) Quarantine(ctx context.Context) error {
	pid, pidFileTime, err := readPIDFile(r.path)
	if err != nil {
		return err
	}
	if err := verifyPIDIdentity(ctx, pid, pidFileTime, r.nebulaBinary); err != nil {
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ESRCH) {
			return nil
		}
		return err
	}
	process, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("find Nebula process for quarantine: %w", err)
	}
	if err := process.Signal(syscall.SIGTERM); err != nil {
		if errors.Is(err, os.ErrProcessDone) || errors.Is(err, syscall.ESRCH) {
			return nil
		}
		return fmt.Errorf("terminate verified Nebula process: %w", err)
	}
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("confirm Nebula process quarantine: %w", ctx.Err())
		case <-deadline.C:
			return errors.New("verified Nebula process did not terminate within 10 seconds")
		case <-ticker.C:
			err := process.Signal(syscall.Signal(0))
			if errors.Is(err, os.ErrProcessDone) || errors.Is(err, syscall.ESRCH) {
				return nil
			}
			if err != nil {
				return fmt.Errorf("confirm Nebula process quarantine: %w", err)
			}
		}
	}
}

func (r *pidRuntime) process(ctx context.Context) (*os.Process, error) {
	pid, pidFileTime, err := readPIDFile(r.path)
	if err != nil {
		return nil, err
	}
	if err := verifyPIDIdentity(ctx, pid, pidFileTime, r.nebulaBinary); err != nil {
		return nil, err
	}
	process, err := os.FindProcess(pid)
	if err != nil {
		return nil, fmt.Errorf("find Nebula process: %w", err)
	}
	return process, nil
}

func readPIDFile(path string) (int, time.Time, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return 0, time.Time{}, fmt.Errorf("inspect Nebula PID file: %w", err)
	}
	if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Size() > 64 {
		return 0, time.Time{}, errors.New("Nebula PID file must be a bounded regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return 0, time.Time{}, fmt.Errorf("open Nebula PID file: %w", err)
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil {
		return 0, time.Time{}, fmt.Errorf("inspect open Nebula PID file: %w", err)
	}
	if !os.SameFile(before, after) {
		return 0, time.Time{}, errors.New("Nebula PID file changed while opening")
	}
	content, err := io.ReadAll(io.LimitReader(file, 65))
	if err != nil {
		return 0, time.Time{}, fmt.Errorf("read Nebula PID file: %w", err)
	}
	value := strings.TrimSpace(string(content))
	pid, err := strconv.Atoi(value)
	if err != nil || pid <= 1 {
		return 0, time.Time{}, errors.New("Nebula PID file does not contain a safe process ID")
	}
	return pid, before.ModTime(), nil
}

func verifyPIDIdentity(ctx context.Context, pid int, pidFileTime time.Time, expectedBinary string) error {
	var executable string
	var startedAt time.Time
	var err error
	if runtime.GOOS == "linux" {
		executable, err = os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
		if err != nil {
			return fmt.Errorf("inspect Nebula process executable: %w", err)
		}
		processInfo, statErr := os.Stat(fmt.Sprintf("/proc/%d", pid))
		if statErr != nil {
			return fmt.Errorf("inspect Nebula process start time: %w", statErr)
		}
		startedAt = processInfo.ModTime()
	} else {
		executable, startedAt, err = inspectProcessWithPS(ctx, pid)
		if err != nil {
			return err
		}
	}
	expectedInfo, err := os.Stat(expectedBinary)
	if err != nil {
		return fmt.Errorf("inspect expected Nebula binary: %w", err)
	}
	actualInfo, err := os.Stat(executable)
	if err != nil {
		return fmt.Errorf("inspect running Nebula binary: %w", err)
	}
	if !os.SameFile(expectedInfo, actualInfo) {
		return fmt.Errorf("PID %d is not the configured Nebula binary", pid)
	}
	if !startedAt.IsZero() && pidFileTime.Before(startedAt.Add(-2*time.Second)) {
		return fmt.Errorf("Nebula PID file predates process %d and may be stale", pid)
	}
	return nil
}

func inspectProcessWithPS(ctx context.Context, pid int) (string, time.Time, error) {
	command := exec.CommandContext(ctx, "ps", "-p", strconv.Itoa(pid), "-o", "comm=", "-o", "lstart=")
	command.Env = append(os.Environ(), "LC_ALL=C")
	output, err := command.Output()
	if err != nil {
		return "", time.Time{}, fmt.Errorf("inspect Nebula process identity: %w", err)
	}
	fields := strings.Fields(string(output))
	if len(fields) < 6 {
		return "", time.Time{}, errors.New("could not inspect Nebula process identity")
	}
	executable := fields[0]
	startedAt, err := time.ParseInLocation("Mon Jan 2 15:04:05 2006", strings.Join(fields[1:6], " "), time.Local)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("parse Nebula process start time: %w", err)
	}
	return executable, startedAt, nil
}
