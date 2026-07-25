package postgresloadgate

import (
	"testing"
)

func TestStatsVisibilityProbePlanReservesApplicationPoolHeadroom(t *testing.T) {
	probes := statsVisibilityProbePlan()
	if len(probes) != 14 {
		t.Fatalf("statistics visibility probes=%d, want 14", len(probes))
	}
	counts := [2]int{}
	ids := make(map[string]struct{}, len(probes))
	for _, probe := range probes {
		if probe.replica < 0 || probe.replica >= len(counts) {
			t.Fatalf("statistics visibility probe has invalid replica %d", probe.replica)
		}
		counts[probe.replica]++
		id := readOperationID("baseline-stats-sync", "ready", probe.ordinal)
		if _, duplicate := ids[id]; duplicate {
			t.Fatalf("statistics visibility operation ID %q is duplicated", id)
		}
		ids[id] = struct{}{}
	}
	if counts != [2]int{7, 7} {
		t.Fatalf("statistics visibility distribution=%v, want [7 7]", counts)
	}
	for replica, count := range counts {
		if count >= statsVisibilityApplicationPoolCapacity {
			t.Fatalf("replica %d probes=%d saturate pool capacity %d", replica+1, count, statsVisibilityApplicationPoolCapacity)
		}
		if statsVisibilityApplicationPoolCapacity-count != statsVisibilityReservedConnections {
			t.Fatalf("replica %d reserved connections=%d, want %d", replica+1, statsVisibilityApplicationPoolCapacity-count, statsVisibilityReservedConnections)
		}
	}
}
