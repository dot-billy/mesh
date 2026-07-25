//go:build windows

package nodeagent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

const windowsNRPTInspectScript = `$ErrorActionPreference='Stop'; Import-Module DnsClient -ErrorAction Stop; function Convert-MeshRecord($item,$includeIdentity) { $namespaces=@($item.Namespace | ForEach-Object {[string]$_}); $servers=@($item.NameServers | ForEach-Object {[string]$_}); $result=[ordered]@{comment='';direct_access_enabled=[bool]$item.DirectAccessEnabled;display_name='';dnssec_enabled=[bool]$item.DnsSecEnabled;dnssec_validation_required=[bool]$item.DnsSecValidationRequired;name_encoding=[string]$item.NameEncoding;name_servers=$servers;namespaces=$namespaces}; if($includeIdentity){$result.comment=[string]$item.Comment;$result.display_name=[string]$item.DisplayName;$result.name=[string]$item.Name}; [pscustomobject]$result }; $configured=@(Get-DnsClientNrptRule -ErrorAction Stop | ForEach-Object {Convert-MeshRecord $_ $true}); $effective=@(Get-DnsClientNrptPolicy -Effective -ErrorAction Stop | ForEach-Object {Convert-MeshRecord $_ $false}); ConvertTo-Json -Compress -Depth 5 -InputObject ([ordered]@{configured=$configured;effective=$effective})`

const windowsNRPTAddScript = `$ErrorActionPreference='Stop'; Import-Module DnsClient -ErrorAction Stop; if($args.Count -ne 4){throw 'invalid Mesh NRPT add arguments'}; Add-DnsClientNrptRule -Namespace $args[0] -NameServers $args[1] -NameEncoding Utf8WithoutMapping -Comment $args[2] -DisplayName $args[3] -ErrorAction Stop | Out-Null; Clear-DnsClientCache -ErrorAction Stop`

const windowsNRPTRemoveScript = `$ErrorActionPreference='Stop'; Import-Module DnsClient -ErrorAction Stop; if($args.Count -ne 1){throw 'invalid Mesh NRPT remove arguments'}; Remove-DnsClientNrptRule -Name $args[0] -Force -ErrorAction Stop; Clear-DnsClientCache -ErrorAction Stop`

type powershellWindowsNRPTBackend struct {
	runner     CommandRunner
	powershell string
	initErr    error
}

func NewNativeDNSManager(runner CommandRunner) NativeDNSReconciler {
	if runner == nil {
		runner = ExecCommandRunner{}
	}
	systemDirectory, err := windows.GetSystemDirectory()
	powershell := ""
	if err == nil {
		powershell = filepath.Join(systemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe")
		if filepath.Clean(powershell) != powershell || !filepath.IsAbs(powershell) {
			err = errors.New("Windows PowerShell system path is not canonical")
		}
	}
	backend := &powershellWindowsNRPTBackend{runner: runner, powershell: powershell, initErr: err}
	return &windowsNativeDNSManager{backend: backend, startProxy: startNativeDNSProxyAtPort}
}

func (backend *powershellWindowsNRPTBackend) Inspect(ctx context.Context) (windowsNRPTSnapshot, error) {
	if err := backend.validate(); err != nil {
		return windowsNRPTSnapshot{}, err
	}
	raw, err := backend.runner.Output(ctx, backend.powershell, windowsPowerShellArguments(windowsNRPTInspectScript)...)
	if err != nil {
		return windowsNRPTSnapshot{}, err
	}
	if len(raw) == 0 || len(raw) > 1<<20 {
		return windowsNRPTSnapshot{}, errors.New("Windows NRPT inventory is empty or oversized")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var snapshot windowsNRPTSnapshot
	if err := decoder.Decode(&snapshot); err != nil {
		return windowsNRPTSnapshot{}, fmt.Errorf("decode Windows NRPT inventory: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return windowsNRPTSnapshot{}, errors.New("Windows NRPT inventory contains trailing data")
	}
	if snapshot.Configured == nil || snapshot.Effective == nil || len(snapshot.Configured) > 1024 || len(snapshot.Effective) > 1024 {
		return windowsNRPTSnapshot{}, errors.New("Windows NRPT inventory is missing or exceeds its rule bound")
	}
	return snapshot, nil
}

func (backend *powershellWindowsNRPTBackend) Add(ctx context.Context, namespace, nameServer string) error {
	if err := backend.validate(); err != nil {
		return err
	}
	if !validWindowsNRPTArgument(namespace) || !validWindowsNRPTArgument(nameServer) {
		return errors.New("Windows NRPT add argument is not canonical")
	}
	arguments := windowsPowerShellArguments(windowsNRPTAddScript)
	arguments = append(arguments, namespace, nameServer, windowsNativeDNSComment, windowsNativeDNSDisplayName)
	return backend.runner.RunQuiet(ctx, backend.powershell, arguments...)
}

func (backend *powershellWindowsNRPTBackend) Remove(ctx context.Context, name string) error {
	if err := backend.validate(); err != nil {
		return err
	}
	if !windowsNRPTRuleNamePattern.MatchString(name) {
		return errors.New("Windows NRPT removal identity is not canonical")
	}
	arguments := windowsPowerShellArguments(windowsNRPTRemoveScript)
	arguments = append(arguments, name)
	return backend.runner.RunQuiet(ctx, backend.powershell, arguments...)
}

func (backend *powershellWindowsNRPTBackend) validate() error {
	if backend == nil || backend.runner == nil {
		return errors.New("Windows NRPT backend is unavailable")
	}
	if backend.initErr != nil {
		return fmt.Errorf("resolve trusted Windows PowerShell: %w", backend.initErr)
	}
	if backend.powershell == "" || !filepath.IsAbs(backend.powershell) || !strings.EqualFold(filepath.Base(backend.powershell), "powershell.exe") {
		return errors.New("trusted Windows PowerShell path is invalid")
	}
	return nil
}

func windowsPowerShellArguments(script string) []string {
	return []string{"-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script}
}

func validWindowsNRPTArgument(value string) bool {
	if value == "" || len(value) > 253 || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '.' && character != '-' {
			return false
		}
	}
	return true
}
