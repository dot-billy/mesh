package windowsinstall

import (
	"errors"
	"fmt"
	"strings"
)

const (
	NodeAgentServiceName        = "MeshNodeAgent"
	NodeAgentServiceDisplayName = "Mesh Node Agent"
	NodeAgentServiceDescription = "Maintains signed Mesh Nebula configuration and supervises the contained Nebula runtime."
)

type NodeAgentServiceContract struct {
	Executable       string
	StatePath        string
	NebulaExecutable string
	NebulaCert       string
	Arguments        []string
}

func NewNodeAgentServiceContract(releaseRoot, statePath string) (NodeAgentServiceContract, error) {
	contract := NodeAgentServiceContract{
		Executable:       windowsJoin(releaseRoot, "bin", "meshctl.exe"),
		StatePath:        statePath,
		NebulaExecutable: windowsJoin(releaseRoot, "bin", "nebula.exe"),
		NebulaCert:       windowsJoin(releaseRoot, "bin", "nebula-cert.exe"),
	}
	contract.Arguments = []string{
		"agent",
		"--state", contract.StatePath,
		"--interval", "1m",
		"--max-config-staleness", "5m",
		"--nebula", contract.NebulaExecutable,
		"--nebula-cert", contract.NebulaCert,
		"--supervise-nebula",
	}
	if err := contract.Validate(); err != nil {
		return NodeAgentServiceContract{}, err
	}
	return contract, nil
}

func (contract NodeAgentServiceContract) Validate() error {
	for name, value := range map[string]string{
		"service executable":         contract.Executable,
		"agent state":                contract.StatePath,
		"Nebula executable":          contract.NebulaExecutable,
		"Nebula certificate utility": contract.NebulaCert,
	} {
		if !cleanWindowsAbsolutePath(value) {
			return fmt.Errorf("Windows %s path must be clean, absolute, and non-root", name)
		}
	}
	for _, executable := range []string{contract.Executable, contract.NebulaExecutable, contract.NebulaCert} {
		if !strings.HasSuffix(strings.ToLower(executable), ".exe") {
			return errors.New("Windows service executables must have .exe names")
		}
	}
	want := []string{
		"agent", "--state", contract.StatePath,
		"--interval", "1m", "--max-config-staleness", "5m",
		"--nebula", contract.NebulaExecutable,
		"--nebula-cert", contract.NebulaCert,
		"--supervise-nebula",
	}
	if len(contract.Arguments) != len(want) {
		return errors.New("Windows node-agent service argument vector is incomplete")
	}
	for index := range want {
		if contract.Arguments[index] != want[index] {
			return fmt.Errorf("Windows node-agent service argument %d differs from its immutable contract", index)
		}
	}
	return nil
}

func windowsJoin(root string, components ...string) string {
	return strings.TrimSuffix(root, `\`) + `\` + strings.Join(components, `\`)
}

func cleanWindowsAbsolutePath(value string) bool {
	if len(value) < 4 || value[1] != ':' || value[2] != '\\' || value[0] < 'A' || value[0] > 'Z' || strings.Contains(value, "/") || strings.ContainsRune(value, 0) {
		return false
	}
	components := strings.Split(value[3:], `\`)
	if len(components) == 0 {
		return false
	}
	for _, component := range components {
		if component == "" || component == "." || component == ".." || strings.HasSuffix(component, ".") || strings.HasSuffix(component, " ") || strings.ContainsAny(component, `<>:"|?*`) {
			return false
		}
	}
	return true
}
