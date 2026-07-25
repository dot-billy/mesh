package runtimetelemetry

import (
	"fmt"
	"reflect"
	"time"

	"mesh/internal/mobileruntime"
)

const MobileRuntimeVersionV1 = mobileruntime.VersionV1

const (
	MaxMobileRuntimeReportBytes    = mobileruntime.MaxReportBytes
	MobileRuntimeFreshnessBound    = 2 * time.Minute
	MobileSuspensionFreshnessBound = 15 * time.Minute
)

const (
	MobileStateTunnelStarting = mobileruntime.StateTunnelStarting
	MobileStateTunnelRunning  = mobileruntime.StateTunnelRunning
	MobileStateTunnelStopping = mobileruntime.StateTunnelStopping
	MobileStateStopped        = mobileruntime.StateStopped
	MobileStateSuspended      = mobileruntime.StateSuspended
	MobileStateQuarantined    = mobileruntime.StateQuarantined
	MobileStateExtensionError = mobileruntime.StateExtensionError
)

// MobileRuntimeReportInput is an independently versioned, extension-authored
// lifecycle observation. It deliberately does not reuse desktop heartbeat
// health or client wall-clock time.
type MobileRuntimeReportInput = mobileruntime.ReportInput

// MobileRuntimeRecord adds only server receive time and bearer-derived node
// identity to the exact accepted extension report.
type MobileRuntimeRecord struct {
	NodeID                 string    `json:"node_id"`
	ReceivedAt             time.Time `json:"received_at"`
	Version                int       `json:"version"`
	InstanceGeneration     int64     `json:"instance_generation"`
	Sequence               int64     `json:"sequence"`
	State                  string    `json:"state"`
	ConfigRevision         int64     `json:"config_revision"`
	ConfigSHA256           string    `json:"config_sha256"`
	CertificateFingerprint string    `json:"certificate_fingerprint"`
	CertificateGeneration  int64     `json:"certificate_generation"`
	EngineIdentity         string    `json:"engine_identity"`
	RuntimeUptimeMS        uint64    `json:"runtime_uptime_ms"`
	PacketsRead            *uint64   `json:"packets_read,omitempty"`
	PacketsWritten         *uint64   `json:"packets_written,omitempty"`
	ErrorCode              string    `json:"error_code,omitempty"`
}

// DecodeMobileRuntimeReportInput rejects duplicate and unknown members,
// invalid UTF-8, trailing values, and oversized input before any field can
// become lifecycle evidence.
func DecodeMobileRuntimeReportInput(
	raw []byte,
) (MobileRuntimeReportInput, error) {
	input, err := mobileruntime.Decode(raw)
	if err != nil {
		return MobileRuntimeReportInput{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	return input, nil
}

// MobileRuntimeProjection is the non-secret operator read model. ServerState
// can become stale or revoked independently of the last client-declared state.
type MobileRuntimeProjection struct {
	Schema                string    `json:"schema"`
	NodeID                string    `json:"node_id"`
	ServerState           string    `json:"server_state"`
	ClientState           string    `json:"client_state"`
	Fresh                 bool      `json:"fresh"`
	ReceivedAt            time.Time `json:"received_at"`
	StaleAfter            time.Time `json:"stale_after"`
	AgeSeconds            int64     `json:"age_seconds"`
	InstanceGeneration    int64     `json:"instance_generation"`
	Sequence              int64     `json:"sequence"`
	ConfigRevision        int64     `json:"config_revision"`
	CertificateGeneration int64     `json:"certificate_generation"`
	EngineIdentity        string    `json:"engine_identity"`
	RuntimeUptimeMS       uint64    `json:"runtime_uptime_ms"`
	PacketsRead           *uint64   `json:"packets_read,omitempty"`
	PacketsWritten        *uint64   `json:"packets_written,omitempty"`
	ErrorCode             string    `json:"error_code,omitempty"`
}

func ProjectMobileRuntime(
	record MobileRuntimeRecord,
	now time.Time,
	revoked bool,
) (MobileRuntimeProjection, error) {
	if err := ValidateMobileRuntimeRecord(record); err != nil {
		return MobileRuntimeProjection{}, err
	}
	now = now.UTC()
	if now.IsZero() || record.ReceivedAt.After(now) {
		return MobileRuntimeProjection{}, fmt.Errorf(
			"%w: mobile projection time is invalid",
			ErrInvalid,
		)
	}
	bound := MobileRuntimeFreshnessBound
	if record.State == MobileStateSuspended {
		bound = MobileSuspensionFreshnessBound
	}
	staleAfter := record.ReceivedAt.Add(bound)
	fresh := now.Before(staleAfter)
	serverState := record.State
	if revoked {
		serverState = "revoked"
		fresh = false
	} else if !fresh {
		serverState = "stale"
	}
	return MobileRuntimeProjection{
		Schema:                "mesh-mobile-runtime-projection-v1",
		NodeID:                record.NodeID,
		ServerState:           serverState,
		ClientState:           record.State,
		Fresh:                 fresh,
		ReceivedAt:            record.ReceivedAt,
		StaleAfter:            staleAfter,
		AgeSeconds:            int64(now.Sub(record.ReceivedAt) / time.Second),
		InstanceGeneration:    record.InstanceGeneration,
		Sequence:              record.Sequence,
		ConfigRevision:        record.ConfigRevision,
		CertificateGeneration: record.CertificateGeneration,
		EngineIdentity:        record.EngineIdentity,
		RuntimeUptimeMS:       record.RuntimeUptimeMS,
		PacketsRead:           cloneUint64(record.PacketsRead),
		PacketsWritten:        cloneUint64(record.PacketsWritten),
		ErrorCode:             record.ErrorCode,
	}, nil
}

func ValidateMobileRuntimeInput(input MobileRuntimeReportInput) error {
	if err := mobileruntime.Validate(input); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	return nil
}

func ValidateMobileRuntimeRecord(record MobileRuntimeRecord) error {
	if !nodeIDPattern.MatchString(record.NodeID) ||
		record.ReceivedAt.IsZero() ||
		record.ReceivedAt.Location() != time.UTC {
		return fmt.Errorf("%w: invalid mobile record identity or receive time", ErrInvalid)
	}
	return ValidateMobileRuntimeInput(record.input())
}

func newMobileRuntimeRecord(
	nodeID string,
	receivedAt time.Time,
	input MobileRuntimeReportInput,
) (MobileRuntimeRecord, error) {
	record := MobileRuntimeRecord{
		NodeID:                 nodeID,
		ReceivedAt:             receivedAt,
		Version:                input.Version,
		InstanceGeneration:     input.InstanceGeneration,
		Sequence:               input.Sequence,
		State:                  input.State,
		ConfigRevision:         input.ConfigRevision,
		ConfigSHA256:           input.ConfigSHA256,
		CertificateFingerprint: input.CertificateFingerprint,
		CertificateGeneration:  input.CertificateGeneration,
		EngineIdentity:         input.EngineIdentity,
		RuntimeUptimeMS:        input.RuntimeUptimeMS,
		PacketsRead:            cloneUint64(input.PacketsRead),
		PacketsWritten:         cloneUint64(input.PacketsWritten),
		ErrorCode:              input.ErrorCode,
	}
	if err := ValidateMobileRuntimeRecord(record); err != nil {
		return MobileRuntimeRecord{}, err
	}
	return record, nil
}

func transitionMobileRuntimeRecord(
	existing *MobileRuntimeRecord,
	candidate MobileRuntimeRecord,
) (MobileRuntimeRecord, bool, error) {
	if existing == nil {
		return cloneMobileRuntimeRecord(candidate), true, nil
	}
	switch {
	case candidate.InstanceGeneration < existing.InstanceGeneration:
		return MobileRuntimeRecord{}, false, ErrReplay
	case candidate.InstanceGeneration == existing.InstanceGeneration &&
		candidate.Sequence < existing.Sequence:
		return MobileRuntimeRecord{}, false, ErrReplay
	case candidate.InstanceGeneration == existing.InstanceGeneration &&
		candidate.Sequence == existing.Sequence:
		if !reflect.DeepEqual(existing.input(), candidate.input()) {
			return MobileRuntimeRecord{}, false, ErrConflict
		}
		return cloneMobileRuntimeRecord(*existing), false, nil
	case candidate.InstanceGeneration-existing.InstanceGeneration > 1_000_000:
		return MobileRuntimeRecord{}, false, ErrInvalid
	}
	if candidate.InstanceGeneration == existing.InstanceGeneration {
		if candidate.RuntimeUptimeMS < existing.RuntimeUptimeMS {
			return MobileRuntimeRecord{}, false, ErrConflict
		}
		if candidate.PacketsRead != nil &&
			existing.PacketsRead != nil &&
			*candidate.PacketsRead < *existing.PacketsRead {
			return MobileRuntimeRecord{}, false, ErrConflict
		}
		if candidate.PacketsWritten != nil &&
			existing.PacketsWritten != nil &&
			*candidate.PacketsWritten < *existing.PacketsWritten {
			return MobileRuntimeRecord{}, false, ErrConflict
		}
	}
	return cloneMobileRuntimeRecord(candidate), true, nil
}

func (record MobileRuntimeRecord) input() MobileRuntimeReportInput {
	return MobileRuntimeReportInput{
		Version:                record.Version,
		InstanceGeneration:     record.InstanceGeneration,
		Sequence:               record.Sequence,
		State:                  record.State,
		ConfigRevision:         record.ConfigRevision,
		ConfigSHA256:           record.ConfigSHA256,
		CertificateFingerprint: record.CertificateFingerprint,
		CertificateGeneration:  record.CertificateGeneration,
		EngineIdentity:         record.EngineIdentity,
		RuntimeUptimeMS:        record.RuntimeUptimeMS,
		PacketsRead:            cloneUint64(record.PacketsRead),
		PacketsWritten:         cloneUint64(record.PacketsWritten),
		ErrorCode:              record.ErrorCode,
	}
}

func cloneMobileRuntimeRecord(record MobileRuntimeRecord) MobileRuntimeRecord {
	record.PacketsRead = cloneUint64(record.PacketsRead)
	record.PacketsWritten = cloneUint64(record.PacketsWritten)
	return record
}
