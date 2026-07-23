package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"mesh/internal/runtimeobserver"
)

type fixedObserver struct {
	snapshot runtimeobserver.Snapshot
	err      error
}

func (observer fixedObserver) Observe(context.Context, runtimeobserver.ValidationContext) (runtimeobserver.Snapshot, error) {
	return observer.snapshot, observer.err
}

func TestRunEmitsStrictlyValidatedSnapshot(t *testing.T) {
	age := uint64(5)
	snapshot := runtimeobserver.Snapshot{
		Schema:            runtimeobserver.SnapshotSchema,
		Nonce:             strings.Repeat("a", runtimeobserver.NonceHexLength),
		ProcessInstanceID: strings.Repeat("b", runtimeobserver.NonceHexLength),
		SampleSequence:    7,
		ProcessUptimeMS:   100,
		Handshakes: runtimeobserver.HandshakeSnapshot{
			CompletedTotal: 1, MostRecentCompletionAgeMS: &age,
		},
		Peers: runtimeobserver.PeerSnapshot{
			Established: 1, AuthenticatedRXWithin2m: 1, AuthenticatedRXWithin5m: 1,
			OldestAuthenticatedRXAgeMS: &age,
		},
		Lighthouses: runtimeobserver.LighthouseSnapshot{
			Configured: 1, Established: 1, AuthenticatedRXWithin2m: 1, AuthenticatedRXWithin5m: 1,
			MostRecentAuthenticatedRXAgeMS: &age,
			Entries: []runtimeobserver.LighthouseEntry{{
				VPNIP: "10.88.0.1", Established: true, LastHandshakeAgeMS: &age, LastAuthenticatedRXAgeMS: &age,
			}},
		},
	}
	var output bytes.Buffer
	if err := run(context.Background(), []string{"--network", "10.88.0.0/24", "--lighthouse", "10.88.0.1"}, &output, fixedObserver{snapshot: snapshot}); err != nil {
		t.Fatal(err)
	}
	var decoded runtimeobserver.Snapshot
	if err := json.Unmarshal(output.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.ProcessInstanceID != snapshot.ProcessInstanceID || decoded.SampleSequence != snapshot.SampleSequence {
		t.Fatalf("snapshot = %#v", decoded)
	}
}

func TestRunRejectsArgumentsAndInvalidObserverOutput(t *testing.T) {
	validClient := fixedObserver{snapshot: runtimeobserver.Snapshot{}}
	tests := [][]string{
		nil,
		{"--network", "10.88.0.1/24"},
		{"--network", "10.88.0.0/24", "--lighthouse", "010.88.0.1"},
		{"--network", "10.88.0.0/24", "--lighthouse", "10.89.0.1"},
		{"--network", "10.88.0.0/24", "extra"},
	}
	for _, args := range tests {
		if err := run(context.Background(), args, &bytes.Buffer{}, validClient); err == nil {
			t.Fatalf("arguments accepted: %q", args)
		}
	}
	if err := run(context.Background(), []string{"--network", "10.88.0.0/24"}, &bytes.Buffer{}, fixedObserver{err: runtimeobserver.ErrTransport}); !errors.Is(err, runtimeobserver.ErrTransport) {
		t.Fatalf("transport error = %v", err)
	}
}
