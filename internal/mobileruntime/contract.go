// Package mobileruntime defines the narrow, platform-neutral iOS Packet
// Tunnel evidence contract. It deliberately has no persistence, HTTP, control,
// or Apple framework dependencies.
package mobileruntime

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"unicode/utf8"
)

const (
	VersionV1           = 1
	MaxReportBytes      = 16 << 10
	MaxExactJSONInteger = uint64(1<<53 - 1)
	StateTunnelStarting = "tunnel-starting"
	StateTunnelRunning  = "tunnel-running"
	StateTunnelStopping = "tunnel-stopping"
	StateStopped        = "stopped"
	StateSuspended      = "suspended"
	StateQuarantined    = "quarantined"
	StateExtensionError = "extension-error"
)

var (
	ErrInvalid       = errors.New("invalid mobile runtime evidence")
	digestPattern    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	errorCodePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
)

type ReportInput struct {
	Version                int     `json:"version"`
	InstanceGeneration     int64   `json:"instance_generation"`
	Sequence               int64   `json:"sequence"`
	State                  string  `json:"state"`
	ConfigRevision         int64   `json:"config_revision"`
	ConfigSHA256           string  `json:"config_sha256"`
	CertificateFingerprint string  `json:"certificate_fingerprint"`
	CertificateGeneration  int64   `json:"certificate_generation"`
	EngineIdentity         string  `json:"engine_identity"`
	RuntimeUptimeMS        uint64  `json:"runtime_uptime_ms"`
	PacketsRead            *uint64 `json:"packets_read,omitempty"`
	PacketsWritten         *uint64 `json:"packets_written,omitempty"`
	ErrorCode              string  `json:"error_code,omitempty"`
}

func Validate(input ReportInput) error {
	if input.Version != VersionV1 ||
		input.InstanceGeneration < 1 ||
		input.InstanceGeneration > int64(MaxExactJSONInteger) ||
		input.Sequence < 1 ||
		input.Sequence > int64(MaxExactJSONInteger) ||
		input.ConfigRevision < 1 ||
		input.ConfigRevision > int64(MaxExactJSONInteger) ||
		input.CertificateGeneration < 1 ||
		input.CertificateGeneration > int64(MaxExactJSONInteger) ||
		input.RuntimeUptimeMS > MaxExactJSONInteger ||
		!digestPattern.MatchString(input.ConfigSHA256) ||
		!digestPattern.MatchString(input.CertificateFingerprint) ||
		!digestPattern.MatchString(input.EngineIdentity) {
		return fmt.Errorf("%w: invalid identity or binding", ErrInvalid)
	}
	switch input.State {
	case StateTunnelRunning:
		if input.PacketsRead == nil ||
			input.PacketsWritten == nil ||
			input.ErrorCode != "" {
			return fmt.Errorf("%w: running evidence is incomplete", ErrInvalid)
		}
	case StateQuarantined, StateExtensionError:
		if input.PacketsRead != nil ||
			input.PacketsWritten != nil ||
			!errorCodePattern.MatchString(input.ErrorCode) {
			return fmt.Errorf("%w: failure evidence is invalid", ErrInvalid)
		}
	case StateTunnelStarting,
		StateTunnelStopping,
		StateStopped,
		StateSuspended:
		if input.PacketsRead != nil ||
			input.PacketsWritten != nil ||
			input.ErrorCode != "" {
			return fmt.Errorf("%w: lifecycle evidence carries invalid detail", ErrInvalid)
		}
	default:
		return fmt.Errorf("%w: unrecognized state", ErrInvalid)
	}
	if (input.PacketsRead != nil &&
		*input.PacketsRead > MaxExactJSONInteger) ||
		(input.PacketsWritten != nil &&
			*input.PacketsWritten > MaxExactJSONInteger) {
		return fmt.Errorf("%w: packet counter is invalid", ErrInvalid)
	}
	return nil
}

func Decode(raw []byte) (ReportInput, error) {
	if len(raw) == 0 || len(raw) > MaxReportBytes || !utf8.Valid(raw) {
		return ReportInput{}, fmt.Errorf(
			"%w: invalid document size or encoding",
			ErrInvalid,
		)
	}
	if err := rejectDuplicateJSONNames(raw); err != nil {
		return ReportInput{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var input ReportInput
	if err := decoder.Decode(&input); err != nil {
		return ReportInput{}, fmt.Errorf("%w: decode report: %v", ErrInvalid, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ReportInput{}, fmt.Errorf("%w: trailing report data", ErrInvalid)
	}
	if err := Validate(input); err != nil {
		return ReportInput{}, err
	}
	return input, nil
}

func rejectDuplicateJSONNames(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := consumeUniqueJSONValue(decoder); err != nil {
		return fmt.Errorf("%w: duplicate or malformed JSON", ErrInvalid)
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: trailing JSON", ErrInvalid)
	}
	return nil
}

func consumeUniqueJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, structured := token.(json.Delim)
	if !structured {
		return nil
	}
	switch delimiter {
	case '{':
		names := make(map[string]struct{})
		for decoder.More() {
			nameToken, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := nameToken.(string)
			if !ok {
				return errors.New("object name is not a string")
			}
			if _, duplicate := names[name]; duplicate {
				return errors.New("duplicate object name")
			}
			names[name] = struct{}{}
			if err := consumeUniqueJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errors.New("invalid object terminator")
		}
		return nil
	case '[':
		for decoder.More() {
			if err := consumeUniqueJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errors.New("invalid array terminator")
		}
		return nil
	default:
		return errors.New("unexpected JSON delimiter")
	}
}
