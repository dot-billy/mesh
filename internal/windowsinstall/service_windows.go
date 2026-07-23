//go:build windows

package windowsinstall

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"

	"mesh/internal/windowssecurity"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

type NodeAgentServiceController struct {
	contract NodeAgentServiceContract
}

func NewNodeAgentServiceController(contract NodeAgentServiceContract) (*NodeAgentServiceController, error) {
	if err := contract.Validate(); err != nil {
		return nil, err
	}
	for label, path := range map[string]string{
		"meshctl": contract.Executable, "nebula": contract.NebulaExecutable, "nebula-cert": contract.NebulaCert,
	} {
		if err := inspectServiceExecutable(path); err != nil {
			return nil, fmt.Errorf("authenticate Windows service %s executable: %w", label, err)
		}
	}
	return &NodeAgentServiceController{contract: contract}, nil
}

func (controller *NodeAgentServiceController) Install() error {
	manager, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect Windows Service Control Manager: %w", err)
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(NodeAgentServiceName)
	if err == nil {
		defer service.Close()
		if err := controller.inspectServiceConfig(service); err != nil {
			return err
		}
		if err := windowssecurity.ProtectPrivateServiceObject(service.Handle); err != nil {
			return fmt.Errorf("protect existing Windows node-agent service object: %w", err)
		}
		return controller.inspectService(service)
	}
	if !errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return fmt.Errorf("inspect Windows node-agent service: %w", err)
	}
	service, err = manager.CreateService(
		NodeAgentServiceName,
		controller.contract.Executable,
		controller.expectedConfig(),
		controller.contract.Arguments...,
	)
	if err != nil {
		return fmt.Errorf("create Windows node-agent service: %w", err)
	}
	defer service.Close()
	if err := windowssecurity.ProtectPrivateServiceObject(service.Handle); err != nil {
		deleteErr := service.Delete()
		return errors.Join(fmt.Errorf("protect Windows node-agent service object: %w", err), deleteErr)
	}
	if err := controller.inspectService(service); err != nil {
		deleteErr := service.Delete()
		return errors.Join(err, deleteErr)
	}
	return nil
}

func (controller *NodeAgentServiceController) InspectInstalled() (bool, error) {
	manager, err := mgr.Connect()
	if err != nil {
		return false, err
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(NodeAgentServiceName)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer service.Close()
	if err := controller.inspectService(service); err != nil {
		return false, err
	}
	return true, nil
}

func (controller *NodeAgentServiceController) StartAndProve(ctx context.Context) (uint32, error) {
	service, manager, err := controller.openExactService()
	if err != nil {
		return 0, err
	}
	defer manager.Disconnect()
	defer service.Close()
	status, err := service.Query()
	if err != nil {
		return 0, err
	}
	if status.State == svc.Stopped {
		if err := service.Start(); err != nil {
			return 0, fmt.Errorf("start Windows node-agent service: %w", err)
		}
	}
	status, err = waitForServiceState(ctx, service, svc.Running)
	if err != nil {
		return 0, err
	}
	if status.ProcessId == 0 {
		return 0, errors.New("running Windows node-agent service has no process identity")
	}
	if err := controller.proveRunningProcess(status); err != nil {
		return 0, err
	}
	return status.ProcessId, nil
}

// InspectRunningAndProve performs no service mutation. It accepts only a
// stable stopped or running state and proves the immutable process image when
// running.
func (controller *NodeAgentServiceController) InspectRunningAndProve() (bool, error) {
	service, manager, err := controller.openExactService()
	if err != nil {
		return false, err
	}
	defer manager.Disconnect()
	defer service.Close()
	status, err := service.Query()
	if err != nil {
		return false, err
	}
	switch status.State {
	case svc.Stopped:
		if status.ProcessId != 0 {
			return false, errors.New("stopped Windows node-agent service retains a process identity")
		}
		return false, nil
	case svc.Running:
		if err := controller.proveRunningProcess(status); err != nil {
			return false, err
		}
		return true, nil
	default:
		return false, fmt.Errorf("Windows node-agent service is in transitional state %d", status.State)
	}
}

func (controller *NodeAgentServiceController) proveRunningProcess(status svc.Status) error {
	if status.State != svc.Running || status.ProcessId == 0 {
		return errors.New("Windows node-agent service is not stably running")
	}
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, status.ProcessId)
	if err != nil {
		return fmt.Errorf("open Windows node-agent service process: %w", err)
	}
	defer windows.CloseHandle(process)
	buffer := make([]uint16, 32768)
	size := uint32(len(buffer))
	if err := windows.QueryFullProcessImageName(process, 0, &buffer[0], &size); err != nil || size == 0 || int(size) > len(buffer) {
		return errors.New("read Windows node-agent service executable path")
	}
	image := windows.UTF16ToString(buffer[:size])
	expected, err := os.Stat(controller.contract.Executable)
	if err != nil {
		return err
	}
	actual, err := os.Stat(image)
	if err != nil || !os.SameFile(expected, actual) {
		return errors.New("Windows node-agent service process is not the immutable configured executable")
	}
	return nil
}

func (controller *NodeAgentServiceController) StopAndProve(ctx context.Context) error {
	service, manager, err := controller.openExactService()
	if err != nil {
		return err
	}
	defer manager.Disconnect()
	defer service.Close()
	status, err := service.Query()
	if err != nil {
		return err
	}
	if status.State != svc.Stopped && status.State != svc.StopPending {
		if _, err := service.Control(svc.Stop); err != nil && !errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) {
			return fmt.Errorf("stop Windows node-agent service: %w", err)
		}
	}
	status, err = waitForServiceState(ctx, service, svc.Stopped)
	if err != nil {
		return err
	}
	if status.ProcessId != 0 {
		return errors.New("stopped Windows node-agent service retains a process identity")
	}
	return nil
}

func (controller *NodeAgentServiceController) DeleteStopped() error {
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(NodeAgentServiceName)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return nil
	}
	if err != nil {
		return err
	}
	status, queryErr := service.Query()
	if queryErr != nil {
		service.Close()
		return queryErr
	}
	if status.State != svc.Stopped || status.ProcessId != 0 {
		service.Close()
		return errors.New("refusing to delete a running Windows node-agent service")
	}
	deleteErr := service.Delete()
	closeErr := service.Close()
	return errors.Join(deleteErr, closeErr)
}

// DeleteStoppedAndProve waits until the Service Control Manager no longer
// exposes the exact stopped service. This covers the normal marked-for-delete
// interval and makes deletion replay-safe after response loss.
func (controller *NodeAgentServiceController) DeleteStoppedAndProve(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := controller.DeleteStopped(); err != nil {
		return err
	}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		manager, err := mgr.Connect()
		if err != nil {
			return err
		}
		service, openErr := manager.OpenService(NodeAgentServiceName)
		if errors.Is(openErr, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			manager.Disconnect()
			return nil
		}
		if openErr == nil {
			inspectErr := controller.inspectService(service)
			closeErr := service.Close()
			disconnectErr := manager.Disconnect()
			if inspectErr != nil || closeErr != nil || disconnectErr != nil {
				return errors.Join(inspectErr, closeErr, disconnectErr)
			}
		} else {
			disconnectErr := manager.Disconnect()
			if !errors.Is(openErr, windows.ERROR_SERVICE_MARKED_FOR_DELETE) {
				return errors.Join(openErr, disconnectErr)
			}
			if disconnectErr != nil {
				return disconnectErr
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func inspectNodeAgentServiceAbsent() (bool, error) {
	manager, err := mgr.Connect()
	if err != nil {
		return false, err
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(NodeAgentServiceName)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return false, service.Close()
}

func (controller *NodeAgentServiceController) openExactService() (*mgr.Service, *mgr.Mgr, error) {
	manager, err := mgr.Connect()
	if err != nil {
		return nil, nil, err
	}
	service, err := manager.OpenService(NodeAgentServiceName)
	if err != nil {
		manager.Disconnect()
		return nil, nil, err
	}
	if err := controller.inspectService(service); err != nil {
		service.Close()
		manager.Disconnect()
		return nil, nil, err
	}
	return service, manager, nil
}

func (controller *NodeAgentServiceController) inspectService(service *mgr.Service) error {
	if err := controller.inspectServiceConfig(service); err != nil {
		return err
	}
	if err := windowssecurity.InspectPrivateServiceObject(service.Handle); err != nil {
		return fmt.Errorf("authenticate Windows node-agent service object: %w", err)
	}
	return nil
}

func (controller *NodeAgentServiceController) inspectServiceConfig(service *mgr.Service) error {
	if service == nil || service.Name != NodeAgentServiceName {
		return errors.New("Windows node-agent service identity is invalid")
	}
	config, err := service.Config()
	if err != nil {
		return err
	}
	want := controller.expectedConfig()
	if config.ServiceType != want.ServiceType || config.StartType != want.StartType || config.ErrorControl != want.ErrorControl ||
		config.BinaryPathName != expectedServiceCommandLine(controller.contract) ||
		!strings.EqualFold(config.ServiceStartName, "LocalSystem") || config.DisplayName != want.DisplayName ||
		config.Description != want.Description || config.SidType != want.SidType || config.DelayedAutoStart ||
		len(config.Dependencies) != 0 || config.LoadOrderGroup != "" {
		return errors.New("Windows node-agent service configuration differs from its immutable contract")
	}
	return nil
}

func (controller *NodeAgentServiceController) expectedConfig() mgr.Config {
	return mgr.Config{
		ServiceType: windows.SERVICE_WIN32_OWN_PROCESS, StartType: mgr.StartAutomatic, ErrorControl: mgr.ErrorNormal,
		DisplayName: NodeAgentServiceDisplayName, Description: NodeAgentServiceDescription,
		ServiceStartName: "LocalSystem", SidType: windows.SERVICE_SID_TYPE_UNRESTRICTED,
	}
}

func expectedServiceCommandLine(contract NodeAgentServiceContract) string {
	result := syscall.EscapeArg(contract.Executable)
	for _, argument := range contract.Arguments {
		result += " " + syscall.EscapeArg(argument)
	}
	return result
}

func inspectServiceExecutable(path string) error {
	before, err := os.Lstat(path)
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return errors.New("service executable is not a real regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return errors.New("service executable changed while opening")
	}
	return windowssecurity.InspectPrivateManagedFileForActor(file, windowssecurity.LocalSystemSID)
}

func waitForServiceState(ctx context.Context, service *mgr.Service, target svc.State) (svc.Status, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		status, err := service.Query()
		if err != nil {
			return svc.Status{}, err
		}
		if status.State == target {
			return status, nil
		}
		if target == svc.Running && status.State == svc.Stopped {
			return svc.Status{}, fmt.Errorf("Windows node-agent service stopped during startup with Win32=%d service=%d", status.Win32ExitCode, status.ServiceSpecificExitCode)
		}
		select {
		case <-ctx.Done():
			return svc.Status{}, ctx.Err()
		case <-ticker.C:
		}
	}
}
