package darwininstall

import (
	"bytes"
	"strings"
	"testing"
)

func TestDarwinInstallStateCanonicalRoundTrip(t *testing.T) {
	highWater := validAuthenticatedDarwinRelease(1, 10, 2, "a", "b")
	active := validAuthenticatedDarwinRelease(1, 9, 2, "c", "d")
	state := validDarwinInstallState(highWater)
	state.Active = &active
	raw, err := encodeDarwinInstallState(state)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeDarwinInstallState(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !sameDarwinInstallState(state, decoded) {
		t.Fatalf("decoded Darwin state differs: %+v", decoded)
	}
	decoded.Active.ArtifactSHA256 = strings.Repeat("e", 64)
	if state.Active.ArtifactSHA256 == decoded.Active.ArtifactSHA256 {
		t.Fatal("decoded Darwin state aliases caller release pointers")
	}
	if raw[len(raw)-1] != '\n' {
		t.Fatal("Darwin state is not newline terminated")
	}
}

func TestDecodeDarwinInstallStateRejectsAmbiguousJSON(t *testing.T) {
	raw, err := encodeDarwinInstallState(validDarwinInstallState(validAuthenticatedDarwinRelease(1, 10, 2, "a", "b")))
	if err != nil {
		t.Fatal(err)
	}
	unknown := append([]byte(nil), raw[:len(raw)-2]...)
	unknown = append(unknown, []byte(`,"unknown":true}`+"\n")...)
	duplicate := bytes.Replace(raw, []byte(`{"schema":`), []byte(`{"schema":"mesh-darwin-install-state-v1","schema":`), 1)
	for name, candidate := range map[string][]byte{
		"unknown": unknown, "duplicate": duplicate, "whitespace": append([]byte(" "), raw...), "trailing": append(append([]byte(nil), raw...), []byte(`{}`)...),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeDarwinInstallState(candidate); err == nil {
				t.Fatal("ambiguous Darwin install state was accepted")
			}
		})
	}
}

func TestDarwinInstallStateTransitionsAllowOnlyAuthorityAdvanceActivationOrRollback(t *testing.T) {
	first := validAuthenticatedDarwinRelease(1, 9, 2, "1", "2")
	initial := validDarwinInstallState(first)
	if err := validateDarwinInstallStateTransition(false, DarwinInstallState{}, initial); err != nil {
		t.Fatal(err)
	}
	activeInitial := initial
	activeInitial.Active = &first
	if err := validateDarwinInstallStateTransition(false, DarwinInstallState{}, activeInitial); err == nil {
		t.Fatal("initial Darwin state claimed an active release")
	}
	candidate := validAuthenticatedDarwinRelease(1, 10, 2, "3", "4")
	advanced, err := initial.AdvanceHighWater(candidate)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateDarwinInstallStateTransition(true, initial, advanced); err != nil {
		t.Fatal(err)
	}
	activated, err := advanced.ActivateAccepted()
	if err != nil {
		t.Fatal(err)
	}
	if err := validateDarwinInstallStateTransition(true, advanced, activated); err != nil {
		t.Fatal(err)
	}
	nextCandidate := validAuthenticatedDarwinRelease(1, 11, 2, "5", "6")
	nextAdvanced, err := activated.AdvanceHighWater(nextCandidate)
	if err != nil {
		t.Fatal(err)
	}
	nextActivated, err := nextAdvanced.ActivateAccepted()
	if err != nil {
		t.Fatal(err)
	}
	rolledBack, err := nextActivated.RollbackPrevious()
	if err != nil {
		t.Fatal(err)
	}
	if err := validateDarwinInstallStateTransition(true, nextActivated, rolledBack); err != nil {
		t.Fatal(err)
	}
	unauthorized := nextActivated
	unauthorized.HighWater = candidate
	if err := validateDarwinInstallStateTransition(true, nextActivated, unauthorized); err == nil {
		t.Fatal("Darwin high-water rollback was accepted")
	}
}
