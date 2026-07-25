// Package windowsinstallercompat defines the Windows-installer-only,
// statically inspectable contract for durable install-state compatibility.
package windowsinstallercompat

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
	Schema      = "mesh-windows-install-state-compatibility-v1"
	FramePrefix = "MESH_WINDOWS_INSTALL_STATE_COMPATIBILITY_V1."
	FrameSuffix = ".END_MESH_WINDOWS_INSTALL_STATE_COMPATIBILITY_V1"

	CurrentReadMinimum  uint64 = 1
	CurrentReadMaximum  uint64 = 1
	CurrentWriteVersion uint64 = 1

	maximumFrameSize = 4 << 10
	currentFrame     = FramePrefix + "eyJzY2hlbWEiOiJtZXNoLXdpbmRvd3MtaW5zdGFsbC1zdGF0ZS1jb21wYXRpYmlsaXR5LXYxIiwicmVhZF9taW4iOjEsInJlYWRfbWF4IjoxLCJ3cml0ZV92ZXJzaW9uIjoxfQ" + FrameSuffix
)

// Identity is retained by the privileged installer and consumed from the same
// PE bytes by offline release tooling.
var Identity = currentFrame

type Contract struct {
	Schema       string `json:"schema"`
	ReadMinimum  uint64 `json:"read_min"`
	ReadMaximum  uint64 `json:"read_max"`
	WriteVersion uint64 `json:"write_version"`
}

func Supported() Contract {
	return Contract{Schema: Schema, ReadMinimum: CurrentReadMinimum, ReadMaximum: CurrentReadMaximum, WriteVersion: CurrentWriteVersion}
}

func Current() (Contract, error) {
	contract, err := ParseIdentity(Identity)
	if err != nil {
		return Contract{}, fmt.Errorf("invalid compiled Windows installer-state compatibility: %w", err)
	}
	if contract != Supported() {
		return Contract{}, errors.New("compiled Windows installer-state compatibility differs from the implementation")
	}
	return contract, nil
}

func ParseIdentity(frame string) (Contract, error) {
	if len(frame) == 0 || len(frame) > maximumFrameSize || !strings.HasPrefix(frame, FramePrefix) || !strings.HasSuffix(frame, FrameSuffix) {
		return Contract{}, errors.New("Windows installer-state compatibility does not have the exact frame")
	}
	encoded := strings.TrimSuffix(strings.TrimPrefix(frame, FramePrefix), FrameSuffix)
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(raw) == 0 || base64.RawURLEncoding.EncodeToString(raw) != encoded {
		return Contract{}, errors.New("Windows installer-state compatibility is not canonical unpadded base64url")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var contract Contract
	if err := decoder.Decode(&contract); err != nil {
		return Contract{}, fmt.Errorf("decode Windows installer-state compatibility: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Contract{}, errors.New("Windows installer-state compatibility contains trailing JSON")
	}
	if err := validate(contract); err != nil {
		return Contract{}, err
	}
	canonical, err := json.Marshal(contract)
	if err != nil || !bytes.Equal(raw, canonical) {
		return Contract{}, errors.New("Windows installer-state compatibility JSON is not canonical")
	}
	return contract, nil
}

func validate(contract Contract) error {
	if contract.Schema != Schema || contract.ReadMinimum != CurrentReadMinimum || contract.ReadMaximum != CurrentReadMaximum || contract.WriteVersion != CurrentWriteVersion {
		return errors.New("Windows installer-state compatibility contract is unsupported")
	}
	return nil
}
