//go:build windows

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"mesh/internal/supervisedchild"
	"mesh/internal/windowssecurity"

	"golang.org/x/sys/windows"
)

const (
	windowsChildExitPollInterval = 50 * time.Millisecond
	windowsJobExitCode           = 0x4d455348 // "MESH"
	windowsStillActive           = 259
)

type windowsPersistentRuntimeGate struct{}

func (windowsPersistentRuntimeGate) Inspect() (bool, error) {
	programData, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, windows.KF_FLAG_DEFAULT)
	if err != nil {
		return false, fmt.Errorf("resolve Windows ProgramData: %w", err)
	}
	path := filepath.Join(programData, "Mesh", "installer", "runtime.enabled")
	if filepath.Clean(path) != path {
		return false, errors.New("Windows persistent runtime gate path is not canonical")
	}
	before, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || before.Size() != int64(len("enabled\n")) {
		return false, errors.New("Windows persistent runtime gate is not an exact real file")
	}
	file, err := os.Open(path)
	if err != nil {
		return false, fmt.Errorf("open Windows persistent runtime gate: %w", err)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return false, errors.New("Windows persistent runtime gate changed while opening")
	}
	if err := windowssecurity.InspectPrivateFileSingleLink(file, windowssecurity.RegularFile); err != nil {
		return false, fmt.Errorf("authenticate Windows persistent runtime gate: %w", err)
	}
	raw, err := io.ReadAll(io.LimitReader(file, int64(len("enabled\n"))+1))
	if err != nil || !bytes.Equal(raw, []byte("enabled\n")) {
		return false, errors.New("Windows persistent runtime gate content is invalid")
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(opened, after) {
		return false, errors.New("Windows persistent runtime gate changed during readback")
	}
	return true, nil
}

func newSupervisedNebulaRuntime(options runtimeOptions) (runtimeController, error) {
	persistent := windowsPersistentRuntimeGate{}
	return authorizeSupervisedRuntime(persistent, func() (runtimeController, error) {
		binary := filepath.Clean(options.nebulaBinary)
		config := filepath.Clean(options.configPath)
		if binary == "" || !filepath.IsAbs(binary) || binary != options.nebulaBinary || !strings.EqualFold(filepath.Ext(binary), ".exe") {
			return nil, errors.New("supervised Windows Nebula binary must be an exact absolute .exe path")
		}
		if config == "" || !filepath.IsAbs(config) || config != options.configPath {
			return nil, errors.New("supervised Windows Nebula config must be an exact absolute path")
		}
		binaryInfo, err := inspectWindowsManagedFile(binary)
		if err != nil {
			return nil, fmt.Errorf("authenticate supervised Windows Nebula executable: %w", err)
		}
		if _, err := inspectWindowsManagedFile(config); err != nil {
			return nil, fmt.Errorf("authenticate supervised Windows Nebula config: %w", err)
		}
		gate := &windowsMemoryGate{}
		supervisor, err := supervisedchild.New(binary, config, windowsChildStarter{binaryInfo: binaryInfo}, gate)
		if err != nil {
			return nil, err
		}
		return &supervisedNebulaRuntime{persistent: persistent, child: supervisor}, nil
	})
}

func inspectWindowsManagedFile(path string) (os.FileInfo, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || !strings.EqualFold(filepath.Clean(resolved), path) {
		return nil, errors.New("Windows managed path cannot traverse a reparse point")
	}
	before, err := os.Lstat(path)
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return nil, errors.New("Windows managed path is not a real regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return nil, errors.New("Windows managed path changed while opening")
	}
	actorSID, err := windowssecurity.CurrentActorSID()
	if err != nil {
		return nil, err
	}
	if err := windowssecurity.InspectPrivateManagedFileForActor(file, actorSID); err != nil {
		return nil, err
	}
	return opened, nil
}

type windowsMemoryGate struct {
	mu   sync.Mutex
	open bool
}

func (gate *windowsMemoryGate) Open() error {
	gate.mu.Lock()
	defer gate.mu.Unlock()
	gate.open = true
	return nil
}

func (gate *windowsMemoryGate) Close() error {
	gate.mu.Lock()
	defer gate.mu.Unlock()
	gate.open = false
	return nil
}

func (gate *windowsMemoryGate) Inspect() (bool, error) {
	gate.mu.Lock()
	defer gate.mu.Unlock()
	return gate.open, nil
}

type windowsChildStarter struct {
	binaryInfo os.FileInfo
}

func (starter windowsChildStarter) Start(ctx context.Context, binary string, arguments []string) (supervisedchild.Process, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if starter.binaryInfo == nil || len(arguments) != 2 || arguments[0] != "-config" {
		return nil, errors.New("Windows supervised-child start contract is incomplete")
	}
	currentBinary, err := inspectWindowsManagedFile(binary)
	if err != nil || !os.SameFile(starter.binaryInfo, currentBinary) {
		return nil, errors.New("Windows Nebula executable changed before start")
	}
	if _, err := inspectWindowsManagedFile(arguments[1]); err != nil {
		return nil, fmt.Errorf("authenticate Windows Nebula config before start: %w", err)
	}

	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, fmt.Errorf("create Windows Nebula job object: %w", err)
	}
	jobOwned := true
	defer func() {
		if jobOwned {
			_ = windows.CloseHandle(job)
		}
	}()
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
		return nil, fmt.Errorf("set Windows Nebula job kill-on-close policy: %w", err)
	}
	if err := proveWindowsJobPolicy(job); err != nil {
		return nil, err
	}

	application, err := windows.UTF16PtrFromString(binary)
	if err != nil {
		return nil, err
	}
	commandLine := syscall.EscapeArg(binary)
	for _, argument := range arguments {
		commandLine += " " + syscall.EscapeArg(argument)
	}
	commandUTF16, err := windows.UTF16FromString(commandLine)
	if err != nil {
		return nil, err
	}
	workingDirectory, err := windows.UTF16PtrFromString(filepath.VolumeName(binary) + string(filepath.Separator))
	if err != nil {
		return nil, err
	}
	emptyEnvironment := []uint16{0, 0}
	startup := windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfo{}))}
	processInfo := windows.ProcessInformation{}
	if err := windows.CreateProcess(
		application, &commandUTF16[0], nil, nil, false,
		windows.CREATE_SUSPENDED|windows.CREATE_NEW_PROCESS_GROUP|windows.CREATE_UNICODE_ENVIRONMENT|windows.CREATE_DEFAULT_ERROR_MODE,
		&emptyEnvironment[0], workingDirectory, &startup, &processInfo,
	); err != nil {
		return nil, fmt.Errorf("create suspended Windows Nebula process: %w", err)
	}
	processOwned, threadOwned := true, true
	cleanup := func() {
		if processOwned {
			_ = windows.TerminateProcess(processInfo.Process, windowsJobExitCode)
			_ = windows.CloseHandle(processInfo.Process)
		}
		if threadOwned {
			_ = windows.CloseHandle(processInfo.Thread)
		}
	}
	if err := windows.AssignProcessToJobObject(job, processInfo.Process); err != nil {
		cleanup()
		return nil, fmt.Errorf("contain suspended Windows Nebula process in job: %w", err)
	}
	if resumed, err := windows.ResumeThread(processInfo.Thread); err != nil || resumed != 1 {
		_ = windows.TerminateJobObject(job, windowsJobExitCode)
		cleanup()
		return nil, fmt.Errorf("resume contained Windows Nebula process: previous suspend count=%d error=%w", resumed, err)
	}
	if err := windows.CloseHandle(processInfo.Thread); err != nil {
		threadOwned = false
		_ = windows.TerminateJobObject(job, windowsJobExitCode)
		cleanup()
		return nil, fmt.Errorf("close Windows Nebula primary-thread handle: %w", err)
	}
	threadOwned = false
	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(processInfo.Process, &creation, &exit, &kernel, &user); err != nil {
		_ = windows.TerminateJobObject(job, windowsJobExitCode)
		cleanup()
		return nil, fmt.Errorf("inspect Windows Nebula process creation identity: %w", err)
	}
	process := &windowsChildProcess{
		process: processInfo.Process, job: job, pid: processInfo.ProcessId,
		binary: binary, arguments: append([]string(nil), arguments...), binaryInfo: starter.binaryInfo,
		creation: creation,
	}
	processOwned, jobOwned = false, false
	if err := ctx.Err(); err != nil {
		return process, errors.Join(err, process.Terminate())
	}
	if err := process.Prove(ctx, binary, arguments); err != nil {
		return process, err
	}
	runtime.KeepAlive(commandUTF16)
	runtime.KeepAlive(emptyEnvironment)
	return process, nil
}

func proveWindowsJobPolicy(job windows.Handle) error {
	var limits windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	if err := windows.QueryInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits)), nil); err != nil {
		return fmt.Errorf("inspect Windows Nebula job policy: %w", err)
	}
	flags := limits.BasicLimitInformation.LimitFlags
	if flags&windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE == 0 || flags&(windows.JOB_OBJECT_LIMIT_BREAKAWAY_OK|windows.JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK) != 0 {
		return errors.New("Windows Nebula job does not enforce non-breakaway kill-on-close containment")
	}
	return nil
}

type windowsChildProcess struct {
	process windows.Handle
	job     windows.Handle
	pid     uint32

	binary     string
	arguments  []string
	binaryInfo os.FileInfo
	creation   windows.Filetime

	mu     sync.Mutex
	closed bool
}

func (process *windowsChildProcess) Prove(ctx context.Context, binary string, arguments []string) error {
	if process == nil || process.process == 0 || process.job == 0 || binary != process.binary || !reflect.DeepEqual(arguments, process.arguments) {
		return errors.New("Windows child proof request differs from the contained process")
	}
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	process.mu.Lock()
	defer process.mu.Unlock()
	if process.closed {
		return errors.New("Windows child process has exited")
	}
	var exitCode uint32
	if err := windows.GetExitCodeProcess(process.process, &exitCode); err != nil || exitCode != windowsStillActive {
		return errors.New("Windows child process is not active")
	}
	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(process.process, &creation, &exit, &kernel, &user); err != nil || creation != process.creation {
		return errors.New("Windows child process creation identity changed")
	}
	if err := proveWindowsJobPolicy(process.job); err != nil {
		return err
	}
	buffer := make([]uint16, 32768)
	size := uint32(len(buffer))
	if err := windows.QueryFullProcessImageName(process.process, 0, &buffer[0], &size); err != nil || size == 0 || int(size) > len(buffer) {
		return errors.New("read Windows child executable path")
	}
	imagePath := windows.UTF16ToString(buffer[:size])
	imageInfo, err := inspectWindowsManagedFile(imagePath)
	if err != nil || !os.SameFile(process.binaryInfo, imageInfo) {
		return errors.New("Windows child executable identity differs from the authenticated Nebula binary")
	}
	if _, err := inspectWindowsManagedFile(process.arguments[1]); err != nil {
		return fmt.Errorf("reauthenticate Windows child config: %w", err)
	}
	return nil
}

func (process *windowsChildProcess) Terminate() error {
	if process == nil {
		return nil
	}
	process.mu.Lock()
	defer process.mu.Unlock()
	if process.closed {
		return nil
	}
	var exitCode uint32
	if err := windows.GetExitCodeProcess(process.process, &exitCode); err == nil && exitCode != windowsStillActive {
		return nil
	}
	if err := windows.TerminateJobObject(process.job, windowsJobExitCode); err != nil {
		return err
	}
	return nil
}

func (process *windowsChildProcess) Wait(ctx context.Context) error {
	if process == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	for {
		process.mu.Lock()
		if process.closed {
			process.mu.Unlock()
			return nil
		}
		handle := process.process
		process.mu.Unlock()
		event, err := windows.WaitForSingleObject(handle, uint32(windowsChildExitPollInterval/time.Millisecond))
		if err != nil {
			return err
		}
		if event == windows.WAIT_OBJECT_0 {
			return process.closeExitedHandles()
		}
		if event != uint32(windows.WAIT_TIMEOUT) {
			return fmt.Errorf("unexpected Windows child wait result %d", event)
		}
		select {
		case <-ctx.Done():
			if err := process.Terminate(); err != nil {
				return err
			}
		case <-time.After(windowsChildExitPollInterval):
		}
	}
}

func (process *windowsChildProcess) closeExitedHandles() error {
	process.mu.Lock()
	defer process.mu.Unlock()
	if process.closed {
		return nil
	}
	var exitCode uint32
	if err := windows.GetExitCodeProcess(process.process, &exitCode); err != nil || exitCode == windowsStillActive {
		return errors.New("Windows child wait completed without a final exit code")
	}
	process.closed = true
	processErr := windows.CloseHandle(process.process)
	jobErr := windows.CloseHandle(process.job)
	process.process, process.job = 0, 0
	return errors.Join(processErr, jobErr)
}
