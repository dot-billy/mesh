package windowsinstall

import "testing"

func TestNodeAgentServiceContractIsExact(t *testing.T) {
	contract, err := NewNodeAgentServiceContract(`C:\ProgramData\Mesh\releases\s00000000000000000001-r0123456789abcdef-a0123456789abcdef`, `C:\ProgramData\Mesh\agent\state.json`)
	if err != nil {
		t.Fatal(err)
	}
	if contract.Arguments[0] != "agent" || contract.Arguments[len(contract.Arguments)-1] != "--supervise-nebula" {
		t.Fatalf("service arguments = %#v", contract.Arguments)
	}
	for index := range contract.Arguments {
		changed := contract
		changed.Arguments = append([]string(nil), contract.Arguments...)
		changed.Arguments[index] += "-drift"
		if err := changed.Validate(); err == nil {
			t.Fatalf("argument mutation %d accepted", index)
		}
	}
	for _, mutate := range []func(*NodeAgentServiceContract){
		func(value *NodeAgentServiceContract) { value.Executable = `meshctl.exe` },
		func(value *NodeAgentServiceContract) { value.StatePath = `C:\` },
		func(value *NodeAgentServiceContract) { value.NebulaExecutable += `.old` },
		func(value *NodeAgentServiceContract) { value.NebulaCert = "" },
	} {
		changed := contract
		mutate(&changed)
		if err := changed.Validate(); err == nil {
			t.Fatal("service contract path mutation accepted")
		}
	}
}
