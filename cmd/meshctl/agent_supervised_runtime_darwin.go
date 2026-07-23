//go:build darwin

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sync"
	"syscall"
	"time"

	"mesh/internal/nodeagent"
	"mesh/internal/supervisedchild"

	"golang.org/x/sys/unix"
)

const packagedDarwinPersistentRuntimeGate = "/private/var/db/mesh-installer/runtime.enabled"

const darwinChildExitPollInterval = 25 * time.Millisecond

type darwinPersistentRuntimeGate struct{}

func (darwinPersistentRuntimeGate) Inspect() (bool, error) {
	return nodeagent.InspectDarwinPersistentRuntimeGate(packagedDarwinPersistentRuntimeGate)
}

func newSupervisedNebulaRuntime(options runtimeOptions) (runtimeController, error) {
	persistent := darwinPersistentRuntimeGate{}
	return authorizeSupervisedRuntime(persistent, func() (runtimeController, error) {
		binary := filepath.Clean(options.nebulaBinary)
		config := filepath.Clean(options.configPath)
		if binary == "" || !filepath.IsAbs(binary) || binary != options.nebulaBinary {
			return nil, errors.New("supervised Darwin Nebula binary must be an exact absolute path")
		}
		if config == "" || !filepath.IsAbs(config) || config != options.configPath {
			return nil, errors.New("supervised Darwin Nebula config must be an exact absolute path")
		}
		resolvedBinary, err := filepath.EvalSymlinks(binary)
		if err != nil || !filepath.IsAbs(resolvedBinary) || filepath.Clean(resolvedBinary) != resolvedBinary {
			return nil, errors.New("resolve supervised Darwin Nebula executable")
		}
		if err := nodeagent.InspectDarwinPackagedExecutable(resolvedBinary); err != nil {
			return nil, fmt.Errorf("authenticate supervised Darwin Nebula executable: %w", err)
		}
		gate := &darwinMemoryGate{}
		supervisor, err := supervisedchild.New(binary, config, darwinChildStarter{resolvedBinary: resolvedBinary}, gate)
		if err != nil {
			return nil, err
		}
		return &supervisedNebulaRuntime{persistent: persistent, child: supervisor}, nil
	})
}

type darwinMemoryGate struct {
	mu   sync.Mutex
	open bool
}

func (gate *darwinMemoryGate) Open() error {
	gate.mu.Lock()
	defer gate.mu.Unlock()
	gate.open = true
	return nil
}

func (gate *darwinMemoryGate) Close() error {
	gate.mu.Lock()
	defer gate.mu.Unlock()
	gate.open = false
	return nil
}

func (gate *darwinMemoryGate) Inspect() (bool, error) {
	gate.mu.Lock()
	defer gate.mu.Unlock()
	return gate.open, nil
}

type darwinChildStarter struct {
	resolvedBinary string
}

func (starter darwinChildStarter) Start(ctx context.Context, binary string, arguments []string) (supervisedchild.Process, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// The lifecycle-cycle context authorizes the start operation, not the
	// lifetime of the managed child. Binding CommandContext to that short-lived
	// context would kill a healthy Nebula process when the cycle returns.
	command := exec.Command(starter.resolvedBinary, arguments...)
	command.Args[0] = binary
	command.Dir = "/"
	command.Env = []string{}
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := command.Start(); err != nil {
		return nil, err
	}
	process := &darwinChildProcess{
		command: command, pid: command.Process.Pid,
		binary: binary, resolvedBinary: starter.resolvedBinary,
		arguments: append([]string(nil), command.Args...), done: make(chan struct{}),
	}
	if err := ctx.Err(); err != nil {
		return process.cleanupFailedStart(err)
	}
	identity, err := inspectDarwinChildIdentity(process.pid)
	if err != nil {
		return process.cleanupFailedStart(fmt.Errorf("inspect started Darwin child identity: %w", err))
	}
	if !identity.validFor(process.pid, os.Getpid()) {
		return process.cleanupFailedStart(errors.New("started Darwin child does not have the exact parent, process group, status, and uid"))
	}
	process.identity = identity
	return process, nil
}

const darwinZombieStatus = int8(5)

type darwinChildIdentity struct {
	pid          int32
	parentPID    int32
	processGroup int32
	startSeconds int64
	startMicros  int32
	status       int8
	uid          uint32
}

func (identity darwinChildIdentity) validFor(pid, parentPID int) bool {
	return identity.pid == int32(pid) &&
		identity.parentPID == int32(parentPID) &&
		identity.processGroup == int32(pid) &&
		identity.status != darwinZombieStatus &&
		identity.uid == 0
}

func (identity darwinChildIdentity) sameProcess(other darwinChildIdentity) bool {
	return identity.pid == other.pid &&
		identity.parentPID == other.parentPID &&
		identity.processGroup == other.processGroup &&
		identity.startSeconds == other.startSeconds &&
		identity.startMicros == other.startMicros &&
		identity.uid == other.uid
}

func inspectDarwinChildIdentity(pid int) (darwinChildIdentity, error) {
	information, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		return darwinChildIdentity{}, err
	}
	return darwinChildIdentity{
		pid: information.Proc.P_pid, parentPID: information.Eproc.Ppid,
		processGroup: information.Eproc.Pgid,
		startSeconds: information.Proc.P_starttime.Sec,
		startMicros:  int32(information.Proc.P_starttime.Usec),
		status:       information.Proc.P_stat, uid: information.Eproc.Ucred.Uid,
	}, nil
}

type darwinChildProcess struct {
	command        *exec.Cmd
	pid            int
	binary         string
	resolvedBinary string
	arguments      []string
	identity       darwinChildIdentity
	done           chan struct{}

	waitOnce sync.Once
	mu       sync.Mutex
	waitErr  error
}

func (process *darwinChildProcess) startWait() {
	process.waitOnce.Do(func() {
		go func() {
			err := process.command.Wait()
			process.mu.Lock()
			process.waitErr = normalizeDarwinChildWait(err)
			process.mu.Unlock()
			close(process.done)
		}()
	})
}

func normalizeDarwinChildWait(err error) error {
	if err == nil {
		return nil
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) && exitError.ProcessState != nil {
		return nil
	}
	return err
}

func (process *darwinChildProcess) cleanupFailedStart(cause error) (supervisedchild.Process, error) {
	killErr := unix.Kill(-process.pid, unix.SIGKILL)
	if errors.Is(killErr, unix.ESRCH) {
		killErr = nil
	}
	process.startWait()
	select {
	case <-process.done:
		process.mu.Lock()
		waitErr := process.waitErr
		process.mu.Unlock()
		if killErr == nil && waitErr == nil {
			return nil, cause
		}
		return process, errors.Join(cause, killErr, waitErr)
	case <-time.After(5 * time.Second):
		return process, errors.Join(cause, killErr, errors.New("Darwin child was not reaped after failed start"))
	}
}

func (process *darwinChildProcess) Prove(ctx context.Context, binary string, arguments []string) error {
	if process == nil || process.command == nil || binary != process.binary || !reflect.DeepEqual(arguments, process.arguments[1:]) {
		return errors.New("Darwin child proof request differs from the started command")
	}
	select {
	case <-process.done:
		return errors.New("Darwin child has exited")
	default:
	}
	identity, err := inspectDarwinChildIdentity(process.pid)
	if err != nil {
		return err
	}
	if !identity.sameProcess(process.identity) || !identity.validFor(process.pid, os.Getpid()) {
		return errors.New("Darwin child process identity changed or became a zombie")
	}
	raw, err := unix.SysctlRaw("kern.procargs2", process.pid)
	if err != nil {
		return err
	}
	return validateDarwinProcessArguments(raw, process.resolvedBinary, process.arguments)
}

func (process *darwinChildProcess) Terminate() error {
	if process == nil {
		return nil
	}
	select {
	case <-process.done:
		return nil
	default:
	}
	if err := unix.Kill(-process.pid, unix.SIGTERM); err != nil && !errors.Is(err, unix.ESRCH) {
		return err
	}
	return nil
}

func (process *darwinChildProcess) Wait(ctx context.Context) error {
	if process == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-process.done:
		return process.waitResult()
	default:
	}
	ticker := time.NewTicker(darwinChildExitPollInterval)
	defer ticker.Stop()
	for {
		identity, err := inspectDarwinChildIdentity(process.pid)
		switch {
		case err == nil && identity.sameProcess(process.identity) && identity.status == darwinZombieStatus:
			process.startWait()
			return process.awaitReap(5*time.Second, nil)
		case err == nil && !identity.sameProcess(process.identity):
			return errors.New("Darwin child identity changed before reap")
		case err != nil && !errors.Is(err, unix.ESRCH) && !errors.Is(err, unix.ENOENT):
			return fmt.Errorf("inspect Darwin child before reap: %w", err)
		case err != nil:
			process.startWait()
			return process.awaitReap(5*time.Second, nil)
		}

		select {
		case <-ctx.Done():
			// Wait has not started, so the tracked child cannot have been
			// reaped and its PID/process-group identity cannot be reused.
			killErr := unix.Kill(-process.pid, unix.SIGKILL)
			if errors.Is(killErr, unix.ESRCH) {
				killErr = nil
			}
			process.startWait()
			return process.awaitReap(5*time.Second, killErr)
		case <-ticker.C:
		}
	}
}

func (process *darwinChildProcess) waitResult() error {
	process.mu.Lock()
	defer process.mu.Unlock()
	return process.waitErr
}

func (process *darwinChildProcess) awaitReap(timeout time.Duration, prior error) error {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-process.done:
		return errors.Join(prior, process.waitResult())
	case <-timer.C:
		return errors.Join(prior, errors.New("Darwin child was not reaped after termination"))
	}
}
