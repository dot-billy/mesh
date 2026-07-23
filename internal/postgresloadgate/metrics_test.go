package postgresloadgate

import (
	"testing"
	"time"
)

func TestNearestRankDoesNotInterpolate(t *testing.T) {
	values := make([]time.Duration, 100)
	for index := range values {
		values[index] = time.Duration(100-index) * time.Millisecond
	}
	for _, test := range []struct {
		percentile int
		want       time.Duration
	}{{1, time.Millisecond}, {50, 50 * time.Millisecond}, {95, 95 * time.Millisecond}, {99, 99 * time.Millisecond}, {100, 100 * time.Millisecond}} {
		got, err := NearestRank(values, test.percentile)
		if err != nil {
			t.Fatal(err)
		}
		if got != test.want {
			t.Fatalf("p%d=%s, want %s", test.percentile, got, test.want)
		}
	}
}

func TestNearestRankRejectsEmptyAndInvalidPercentile(t *testing.T) {
	if _, err := NearestRank(nil, 95); err == nil {
		t.Fatal("empty nearest-rank population was accepted")
	}
	if _, err := NearestRank([]time.Duration{time.Second}, 0); err == nil {
		t.Fatal("zero percentile was accepted")
	}
	if _, err := NearestRank([]time.Duration{time.Second}, 101); err == nil {
		t.Fatal("percentile above 100 was accepted")
	}
}

func TestValidateLatencyBudgetBoundaries(t *testing.T) {
	input := LatencyBudgetInput{
		Writes:       DurationSummary{Count: ExpectedWrites, P95Micros: MaximumWriteP95.Microseconds(), P99Micros: MaximumWriteP99.Microseconds(), MaximumMicros: MaximumWrite.Microseconds()},
		Reads:        DurationSummary{Count: SoakReads, P95Micros: MaximumReadP95.Microseconds(), P99Micros: MaximumReadP99.Microseconds(), MaximumMicros: MaximumRead.Microseconds()},
		LoadDuration: time.Duration(float64(ExpectedLoadWrites) / MinimumLoadWritesPerSecond * float64(time.Second)),
		SoakDuration: MinimumSoakDuration, SuccessfulLoadWrites: ExpectedLoadWrites,
	}
	if err := ValidateLatencyBudget(input); err != nil {
		t.Fatalf("exact budget boundary rejected: %v", err)
	}
	input.Writes.P99Micros++
	if err := ValidateLatencyBudget(input); err == nil {
		t.Fatal("write p99 above budget was accepted")
	}
}
