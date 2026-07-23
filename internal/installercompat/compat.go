// Package installercompat defines the installer-only, statically inspectable
// contract for on-disk installer-state compatibility. The frame is embedded
// only in mesh-install; release tooling copies the exact contract into the
// threshold-authenticated Linux bundle metadata.
package installercompat

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	Schema      = "mesh-installer-state-compatibility-v1"
	FramePrefix = "MESH_INSTALLER_STATE_COMPATIBILITY_V1."
	FrameSuffix = ".END_MESH_INSTALLER_STATE_COMPATIBILITY_V1"

	// The current installer can migrate legacy v2 state, reads the root-aware
	// v3 state it writes, and never writes a version it cannot subsequently read.
	CurrentReadMinimum  uint64 = 2
	CurrentReadMaximum  uint64 = 3
	CurrentWriteVersion uint64 = 3

	maximumFrameSize = 4 << 10
	maximumVersion   = 1 << 16

	currentFrame = FramePrefix + "eyJzY2hlbWEiOiJtZXNoLWluc3RhbGxlci1zdGF0ZS1jb21wYXRpYmlsaXR5LXYxIiwicmVhZF9taW4iOjIsInJlYWRfbWF4IjozLCJ3cml0ZV92ZXJzaW9uIjozfQ" + FrameSuffix
)

// Identity is deliberately a framed variable so the running installer and a
// static ELF inspector consume the same exact bytes.
var Identity = currentFrame

type Contract struct {
	Schema       string `json:"schema"`
	ReadMinimum  uint64 `json:"read_min"`
	ReadMaximum  uint64 `json:"read_max"`
	WriteVersion uint64 `json:"write_version"`
}

func Supported() Contract {
	return Contract{
		Schema: Schema, ReadMinimum: CurrentReadMinimum,
		ReadMaximum: CurrentReadMaximum, WriteVersion: CurrentWriteVersion,
	}
}

func (contract Contract) Reads(version uint64) bool {
	return version >= contract.ReadMinimum && version <= contract.ReadMaximum
}

func Validate(contract Contract) error { return validate(contract) }

func Current() (Contract, error) {
	contract, err := ParseIdentity(Identity)
	if err != nil {
		return Contract{}, fmt.Errorf("invalid compiled installer-state compatibility: %w", err)
	}
	if contract != Supported() {
		return Contract{}, errors.New("compiled installer-state compatibility differs from this installer's implementation")
	}
	return contract, nil
}

func EncodeIdentity(contract Contract) (string, error) {
	if err := validate(contract); err != nil {
		return "", err
	}
	raw, err := json.Marshal(contract)
	if err != nil {
		return "", fmt.Errorf("encode installer-state compatibility: %w", err)
	}
	frame := FramePrefix + base64.RawURLEncoding.EncodeToString(raw) + FrameSuffix
	if len(frame) > maximumFrameSize {
		return "", errors.New("installer-state compatibility frame exceeds its size bound")
	}
	return frame, nil
}

func ParseIdentity(frame string) (Contract, error) {
	if len(frame) == 0 || len(frame) > maximumFrameSize ||
		!strings.HasPrefix(frame, FramePrefix) || !strings.HasSuffix(frame, FrameSuffix) {
		return Contract{}, errors.New("installer-state compatibility does not have the exact frame")
	}
	encoded := strings.TrimSuffix(strings.TrimPrefix(frame, FramePrefix), FrameSuffix)
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(raw) == 0 || base64.RawURLEncoding.EncodeToString(raw) != encoded {
		return Contract{}, errors.New("installer-state compatibility is not canonical unpadded base64url")
	}
	if err := validateStrictJSON(raw); err != nil {
		return Contract{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var contract Contract
	if err := decoder.Decode(&contract); err != nil {
		return Contract{}, fmt.Errorf("decode installer-state compatibility: %w", err)
	}
	if err := validate(contract); err != nil {
		return Contract{}, err
	}
	canonical, err := json.Marshal(contract)
	if err != nil || !bytes.Equal(raw, canonical) {
		return Contract{}, errors.New("installer-state compatibility JSON is not canonical")
	}
	return contract, nil
}

func validate(contract Contract) error {
	if contract.Schema != Schema {
		return fmt.Errorf("unsupported installer-state compatibility schema %q", contract.Schema)
	}
	if contract.ReadMinimum == 0 || contract.ReadMaximum == 0 || contract.WriteVersion == 0 ||
		contract.ReadMinimum > contract.WriteVersion || contract.WriteVersion > contract.ReadMaximum ||
		contract.ReadMaximum > maximumVersion {
		return errors.New("installer-state read range and write version must be positive, bounded, ordered, and self-readable")
	}
	return nil
}

func validateStrictJSON(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := consumeJSON(decoder); err != nil {
		return fmt.Errorf("invalid installer-state compatibility JSON: %w", err)
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("installer-state compatibility contains trailing JSON")
		}
		return fmt.Errorf("installer-state compatibility trailing JSON: %w", err)
	}
	return nil
}

func consumeJSON(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("JSON object key is not a string")
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("duplicate JSON field %q", key)
			}
			seen[key] = struct{}{}
			if err := consumeJSON(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("invalid JSON object terminator")
		}
	case '[':
		for decoder.More() {
			if err := consumeJSON(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("invalid JSON array terminator")
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	return nil
}
