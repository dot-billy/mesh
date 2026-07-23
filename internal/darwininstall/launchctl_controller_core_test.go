package darwininstall

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

type recordingLaunchctlRunner struct {
	events  []string
	results []error
}

func (runner *recordingLaunchctlRunner) Run(arguments ...string) error {
	runner.events = append(runner.events, strings.Join(arguments, " "))
	if len(runner.results) == 0 {
		return nil
	}
	result := runner.results[0]
	runner.results = runner.results[1:]
	return result
}

func TestLaunchctlBootoutProvesLoadedAndAbsentStatesWithoutStatusParsing(t *testing.T) {
	failure := errors.New("injected launchctl failure")
	for name, test := range map[string]struct {
		results []error
		want    []string
	}{
		"loaded": {results: []error{nil}, want: []string{"bootout system/io.mesh.node-agent"}},
		"absent": {results: []error{failure, nil, nil}, want: []string{
			"bootout system/io.mesh.node-agent", "bootstrap system /exact/recovery.plist", "bootout system/io.mesh.node-agent",
		}},
		"raced": {results: []error{failure, failure, nil}, want: []string{
			"bootout system/io.mesh.node-agent", "bootstrap system /exact/recovery.plist", "bootout system/io.mesh.node-agent",
		}},
	} {
		t.Run(name, func(t *testing.T) {
			runner := &recordingLaunchctlRunner{results: append([]error(nil), test.results...)}
			if err := (launchctlServiceOperations{runner: runner}).Bootout("/exact/recovery.plist"); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(runner.events, test.want) {
				t.Fatalf("launchctl events = %q, want %q", runner.events, test.want)
			}
		})
	}
}

func TestLaunchctlBootoutRejectsUnprovedAbsence(t *testing.T) {
	failure := errors.New("injected launchctl failure")
	runner := &recordingLaunchctlRunner{results: []error{failure, failure, failure}}
	err := (launchctlServiceOperations{runner: runner}).Bootout("/exact/recovery.plist")
	if err == nil || !strings.Contains(err.Error(), "could not prove service absence") || len(runner.events) != 3 {
		t.Fatalf("unproved launchctl absence = events %q, err %v", runner.events, err)
	}
}

func TestLaunchctlBootstrapUsesExactSystemDomainAndLivePlist(t *testing.T) {
	runner := &recordingLaunchctlRunner{}
	if err := (launchctlServiceOperations{runner: runner}).Bootstrap("/Library/LaunchDaemons/io.mesh.node-agent.plist"); err != nil {
		t.Fatal(err)
	}
	want := []string{"bootstrap system /Library/LaunchDaemons/io.mesh.node-agent.plist"}
	if !reflect.DeepEqual(runner.events, want) {
		t.Fatalf("launchctl bootstrap events = %q, want %q", runner.events, want)
	}
}

func TestLaunchctlCommandContractRejectsTargetAndPlistDrift(t *testing.T) {
	contract, err := newLaunchctlCommandContract(
		launchctlServiceIdentity{domain: "system", target: "system/io.mesh.node-agent"},
		"/exact/recovery.plist",
		"/Library/LaunchDaemons/io.mesh.node-agent.plist",
	)
	if err != nil {
		t.Fatal(err)
	}
	for name, arguments := range map[string][]string{
		"other target": {"bootout", "system/io.mesh.other"},
		"other plist":  {"bootstrap", "system", "/Library/LaunchDaemons/io.mesh.other.plist"},
		"other domain": {"bootstrap", "gui/501", "/exact/recovery.plist"},
		"extra flag":   {"bootout", "system/io.mesh.node-agent", "unexpected"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := contract.validate(arguments); err == nil {
				t.Fatal("out-of-contract launchctl command was accepted")
			}
		})
	}
	for _, arguments := range [][]string{
		{"bootout", "system/io.mesh.node-agent"},
		{"bootstrap", "system", "/exact/recovery.plist"},
		{"bootstrap", "system", "/Library/LaunchDaemons/io.mesh.node-agent.plist"},
	} {
		if err := contract.validate(arguments); err != nil {
			t.Fatalf("exact launchctl command %q returned %v", arguments, err)
		}
	}
}

func TestLaunchctlCommandContractRejectsUnsafeConstruction(t *testing.T) {
	for name, identity := range map[string]launchctlServiceIdentity{
		"other domain": {domain: "gui/501", target: "gui/501/io.mesh.node-agent"},
		"empty label":  {domain: "system", target: "system/"},
		"nested label": {domain: "system", target: "system/io.mesh/node-agent"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := newLaunchctlCommandContract(identity, "/exact/service.plist"); err == nil {
				t.Fatal("unsafe launchctl service identity was accepted")
			}
		})
	}
	for name, paths := range map[string][]string{
		"none":      nil,
		"relative":  {"service.plist"},
		"root":      {"/"},
		"duplicate": {"/exact/service.plist", "/exact/service.plist"},
		"too many":  {"/one.plist", "/two.plist", "/three.plist"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := newLaunchctlCommandContract(launchctlServiceIdentity{}, paths...); err == nil {
				t.Fatal("unsafe launchctl plist contract was accepted")
			}
		})
	}
}
