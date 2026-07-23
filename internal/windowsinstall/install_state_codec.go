package windowsinstall

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
)

const maximumWindowsInstallStateBytes = 64 << 10

func MarshalWindowsInstallState(state WindowsInstallState) ([]byte, error) {
	if err := state.Validate(); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(state)
	if err != nil {
		return nil, fmt.Errorf("encode Windows install state: %w", err)
	}
	raw = append(raw, '\n')
	if len(raw) > maximumWindowsInstallStateBytes {
		return nil, errors.New("Windows install state exceeds its size bound")
	}
	return raw, nil
}

func ParseWindowsInstallState(raw []byte) (WindowsInstallState, error) {
	if len(raw) < 2 || len(raw) > maximumWindowsInstallStateBytes {
		return WindowsInstallState{}, errors.New("Windows install state is empty or oversized")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var state WindowsInstallState
	if err := decoder.Decode(&state); err != nil {
		return WindowsInstallState{}, fmt.Errorf("decode Windows install state: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return WindowsInstallState{}, errors.New("Windows install state contains multiple JSON values")
		}
		return WindowsInstallState{}, fmt.Errorf("decode trailing Windows install-state data: %w", err)
	}
	canonical, err := MarshalWindowsInstallState(state)
	if err != nil {
		return WindowsInstallState{}, err
	}
	if !bytes.Equal(raw, canonical) {
		return WindowsInstallState{}, errors.New("Windows install state is not canonical")
	}
	return state, nil
}

func validateWindowsInstallStateTransition(current *WindowsInstallState, next WindowsInstallState) error {
	if err := next.Validate(); err != nil {
		return err
	}
	if current == nil {
		if next.Active != nil || next.Previous != nil {
			return errors.New("initial Windows install state must accept high-water authority before activation")
		}
		return nil
	}
	if err := current.Validate(); err != nil {
		return err
	}
	if current.Schema != next.Schema || current.BootstrapTrustSHA256 != next.BootstrapTrustSHA256 ||
		current.Channel != next.Channel || current.Arch != next.Arch {
		return errors.New("Windows install-state transition changed fixed installer authority")
	}
	if reflect.DeepEqual(*current, next) {
		return nil
	}
	if current.HighWater != next.HighWater {
		expected, err := current.AdvanceHighWater(next.HighWater)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(expected, next) {
			return errors.New("Windows install-state high-water transition changed active release state")
		}
		return nil
	}
	if activated, err := current.ActivateAccepted(); err == nil && reflect.DeepEqual(activated, next) {
		return nil
	}
	if rolledBack, err := current.RollbackPrevious(); err == nil && reflect.DeepEqual(rolledBack, next) {
		return nil
	}
	if deactivated, err := current.DeactivateRuntime(); err == nil && reflect.DeepEqual(deactivated, next) {
		return nil
	}
	return errors.New("Windows install-state active/previous transition is not an exact activation, rollback, or runtime deactivation")
}
