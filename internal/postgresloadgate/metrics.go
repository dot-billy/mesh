// Package postgresloadgate implements the bounded, test-only PostgreSQL
// intended-workload gate used by scripts/postgres-load-soak-smoke.sh.
package postgresloadgate

import (
	"errors"
	"fmt"
	"math"
	"sort"
	"time"
)

const (
	LoadNodeCreates    = 48
	LoadNodeReissues   = 48
	SoakNodeRevokes    = 24
	LoadSessionCreates = 68
	LoadSessionRevokes = 56
	SoakSessionRevokes = 12
	SoakReads          = 108
	WorkerConcurrency  = 8

	ExpectedControlWrites  = LoadNodeCreates + LoadNodeReissues + SoakNodeRevokes
	ExpectedIdentityWrites = LoadSessionCreates + LoadSessionRevokes + SoakSessionRevokes
	ExpectedLoadWrites     = LoadNodeCreates + LoadNodeReissues + LoadSessionCreates + LoadSessionRevokes
	ExpectedWrites         = ExpectedControlWrites + ExpectedIdentityWrites
)

const (
	SoakDuration        = 30 * time.Second
	MinimumSoakDuration = 25 * time.Second
	MaximumSoakDuration = 45 * time.Second

	MaximumWriteP95 = 2 * time.Second
	MaximumWriteP99 = 5 * time.Second
	MaximumWrite    = 10 * time.Second
	MaximumReadP95  = 750 * time.Millisecond
	MaximumReadP99  = 2 * time.Second
	MaximumRead     = 5 * time.Second

	MinimumLoadWritesPerSecond   = 8.0
	MaximumWALBytes              = 128 << 20
	MaximumAverageWALPerWrite    = 512 << 10
	MaximumWALBuffersFull        = 8
	MaximumDatabaseBytes         = 128 << 20
	MaximumDocumentBytes         = 2 << 20
	MaximumVacuumDuration        = 10 * time.Second
	MaximumDeadTuplesAfterVacuum = 4
	MaximumApplicationRSSBytes   = 192 << 20
	MaximumPostgresMemoryBytes   = 384 << 20
)

// DurationSummary uses nearest-rank percentiles: sort ascending, choose the
// value at one-based rank ceil(percentile/100*N), and clamp that rank to N.
// This definition intentionally does not interpolate between observations.
type DurationSummary struct {
	Count         int   `json:"count"`
	P95Micros     int64 `json:"p95_micros"`
	P99Micros     int64 `json:"p99_micros"`
	MaximumMicros int64 `json:"maximum_micros"`
}

func NearestRank(values []time.Duration, percentile int) (time.Duration, error) {
	if len(values) == 0 {
		return 0, errors.New("nearest-rank percentile requires at least one value")
	}
	if percentile < 1 || percentile > 100 {
		return 0, errors.New("nearest-rank percentile must be between 1 and 100")
	}
	ordered := append([]time.Duration(nil), values...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i] < ordered[j] })
	rank := int(math.Ceil(float64(percentile) / 100 * float64(len(ordered))))
	if rank < 1 {
		rank = 1
	}
	if rank > len(ordered) {
		rank = len(ordered)
	}
	return ordered[rank-1], nil
}

func SummarizeDurations(values []time.Duration) (DurationSummary, error) {
	p95, err := NearestRank(values, 95)
	if err != nil {
		return DurationSummary{}, err
	}
	p99, err := NearestRank(values, 99)
	if err != nil {
		return DurationSummary{}, err
	}
	maximum, err := NearestRank(values, 100)
	if err != nil {
		return DurationSummary{}, err
	}
	return DurationSummary{
		Count: len(values), P95Micros: p95.Microseconds(), P99Micros: p99.Microseconds(), MaximumMicros: maximum.Microseconds(),
	}, nil
}

type LatencyBudgetInput struct {
	Writes               DurationSummary
	Reads                DurationSummary
	LoadDuration         time.Duration
	SoakDuration         time.Duration
	SuccessfulLoadWrites int
}

func ValidateLatencyBudget(input LatencyBudgetInput) error {
	if input.Writes.Count != ExpectedWrites {
		return fmt.Errorf("write latency sample count=%d, want %d", input.Writes.Count, ExpectedWrites)
	}
	if input.Reads.Count != SoakReads {
		return fmt.Errorf("read latency sample count=%d, want %d", input.Reads.Count, SoakReads)
	}
	if input.SuccessfulLoadWrites != ExpectedLoadWrites {
		return fmt.Errorf("successful load writes=%d, want %d", input.SuccessfulLoadWrites, ExpectedLoadWrites)
	}
	if input.LoadDuration <= 0 {
		return errors.New("load duration must be positive")
	}
	throughput := float64(input.SuccessfulLoadWrites) / input.LoadDuration.Seconds()
	if throughput < MinimumLoadWritesPerSecond {
		return fmt.Errorf("load throughput=%.3f writes/s, want at least %.3f", throughput, MinimumLoadWritesPerSecond)
	}
	if input.SoakDuration < MinimumSoakDuration || input.SoakDuration > MaximumSoakDuration {
		return fmt.Errorf("soak duration=%s, want %s..%s", input.SoakDuration, MinimumSoakDuration, MaximumSoakDuration)
	}
	if time.Duration(input.Writes.P95Micros)*time.Microsecond > MaximumWriteP95 ||
		time.Duration(input.Writes.P99Micros)*time.Microsecond > MaximumWriteP99 ||
		time.Duration(input.Writes.MaximumMicros)*time.Microsecond > MaximumWrite {
		return fmt.Errorf("write latency exceeds p95=%s p99=%s max=%s budgets: %+v", MaximumWriteP95, MaximumWriteP99, MaximumWrite, input.Writes)
	}
	if time.Duration(input.Reads.P95Micros)*time.Microsecond > MaximumReadP95 ||
		time.Duration(input.Reads.P99Micros)*time.Microsecond > MaximumReadP99 ||
		time.Duration(input.Reads.MaximumMicros)*time.Microsecond > MaximumRead {
		return fmt.Errorf("read latency exceeds p95=%s p99=%s max=%s budgets: %+v", MaximumReadP95, MaximumReadP99, MaximumRead, input.Reads)
	}
	return nil
}
