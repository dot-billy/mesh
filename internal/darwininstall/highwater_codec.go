package darwininstall

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

const maximumDarwinInstallStateSize = 128 << 10

func encodeDarwinInstallState(state DarwinInstallState) ([]byte, error) {
	state = cloneDarwinInstallState(state)
	if err := state.Validate(); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(state)
	if err != nil {
		return nil, fmt.Errorf("encode Darwin install state: %w", err)
	}
	raw = append(raw, '\n')
	if len(raw) == 0 || len(raw) > maximumDarwinInstallStateSize {
		return nil, errors.New("Darwin install state exceeds its size bound")
	}
	return raw, nil
}

func decodeDarwinInstallState(raw []byte) (DarwinInstallState, error) {
	if len(raw) == 0 || len(raw) > maximumDarwinInstallStateSize || !utf8.Valid(raw) {
		return DarwinInstallState{}, errors.New("Darwin install-state bytes are invalid or outside their bound")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var state DarwinInstallState
	if err := decoder.Decode(&state); err != nil {
		return DarwinInstallState{}, fmt.Errorf("decode Darwin install state: %w", err)
	}
	if token, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err != nil {
			return DarwinInstallState{}, fmt.Errorf("decode Darwin install-state trailing data: %w", err)
		}
		return DarwinInstallState{}, fmt.Errorf("decode Darwin install-state trailing token %v", token)
	}
	canonical, err := encodeDarwinInstallState(state)
	if err != nil {
		return DarwinInstallState{}, err
	}
	if !bytes.Equal(raw, canonical) {
		return DarwinInstallState{}, errors.New("Darwin install state is not canonical")
	}
	return cloneDarwinInstallState(state), nil
}

func validateDarwinInstallStateTransition(found bool, current, next DarwinInstallState) error {
	if err := next.Validate(); err != nil {
		return err
	}
	if !found {
		if next.Active != nil || next.Previous != nil {
			return errors.New("initial Darwin install state cannot claim an activated release")
		}
		return nil
	}
	if err := current.Validate(); err != nil {
		return fmt.Errorf("current Darwin install state: %w", err)
	}
	if next.Schema != current.Schema || next.BootstrapTrustSHA256 != current.BootstrapTrustSHA256 ||
		next.Channel != current.Channel || next.Arch != current.Arch {
		return errors.New("Darwin install-state schema, trust, channel, and architecture are immutable")
	}
	if sameDarwinInstallState(current, next) {
		return nil
	}
	if sameAuthenticatedDarwinReleasePointer(current.Active, next.Active) &&
		sameAuthenticatedDarwinReleasePointer(current.Previous, next.Previous) {
		expected, err := current.AdvanceHighWater(next.HighWater)
		if err == nil && sameDarwinInstallState(expected, next) {
			return nil
		}
		return errors.New("Darwin high-water transition is not an exact authorized advance")
	}
	if next.HighWater != current.HighWater {
		return errors.New("Darwin active-release transition cannot change high-water authority")
	}
	if expected, err := current.ActivateAccepted(); err == nil && sameDarwinInstallState(expected, next) {
		return nil
	}
	if expected, err := current.RollbackPrevious(); err == nil && sameDarwinInstallState(expected, next) {
		return nil
	}
	return errors.New("Darwin active-release transition is neither exact activation nor recorded rollback")
}

func sameDarwinInstallState(left, right DarwinInstallState) bool {
	return left.Schema == right.Schema && left.BootstrapTrustSHA256 == right.BootstrapTrustSHA256 &&
		left.Channel == right.Channel && left.Arch == right.Arch && left.HighWater == right.HighWater &&
		sameAuthenticatedDarwinReleasePointer(left.Active, right.Active) &&
		sameAuthenticatedDarwinReleasePointer(left.Previous, right.Previous)
}

func sameAuthenticatedDarwinReleasePointer(left, right *AuthenticatedDarwinRelease) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}
