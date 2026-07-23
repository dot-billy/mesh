package postgresloadgate

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestHTTPWorkloadClientDisablesProxyAndRedirects(t *testing.T) {
	var redirected atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		redirected.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Redirect(w, &http.Request{}, target.URL, http.StatusTemporaryRedirect)
	}))
	defer source.Close()
	ledger := newOperationLedger()
	client, err := newHTTPWorkloadClient(
		[2]string{source.URL, target.URL}, source.URL, base64.RawURLEncoding.EncodeToString(make([]byte, 32)), ledger, &secretSink{closed: true},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer client.close()
	transport, ok := client.client.Transport.(*http.Transport)
	if !ok || transport.Proxy != nil {
		t.Fatal("HTTP workload client retained environment proxy behavior")
	}
	_, err = client.perform(context.Background(), requestSpec{
		id: "redirect.test", stage: "test", kind: "redirect", replica: 0,
		method: http.MethodPost, path: "/", body: []byte(`{}`), write: true, expectedStatus: http.StatusOK,
	})
	if err == nil {
		t.Fatal("redirecting load operation was accepted")
	}
	if redirected.Load() != 0 {
		t.Fatalf("redirect target received %d requests, want 0", redirected.Load())
	}
	records := ledger.snapshot()
	if len(records) != 1 || records[0].Attempts != 1 {
		t.Fatalf("redirect operation records=%+v", records)
	}
}

func TestPacedSoakCancellationDrainsStartedTasks(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	done := make(chan struct{})
	result := make(chan error, 1)
	tasks := []workloadTask{
		func(ctx context.Context) error {
			close(started)
			<-ctx.Done()
			close(done)
			return ctx.Err()
		},
		func(context.Context) error { return nil },
	}
	go func() {
		_, err := pacedSoak(ctx, tasks, 2*time.Second)
		result <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("first paced task did not start")
	}
	cancel()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("canceled soak returned success")
		}
		select {
		case <-done:
		default:
			t.Fatal("paced soak returned before its started task drained")
		}
	case <-time.After(time.Second):
		t.Fatal("canceled paced soak did not return after draining")
	}
}

func TestSoakWritesAlternateReplicas(t *testing.T) {
	counts := [2]int{}
	for cycle := range 36 {
		counts[soakWriteReplica(cycle)]++
	}
	if counts != [2]int{18, 18} {
		t.Fatalf("soak write distribution=%v, want [18 18]", counts)
	}
}

func TestValidateReadyResponseUsesServerJSONContract(t *testing.T) {
	if err := validateReadyResponse([]byte("{\"status\":\"ready\"}\n")); err != nil {
		t.Fatalf("valid readiness JSON rejected: %v", err)
	}
	for _, raw := range [][]byte{
		[]byte("ready\n"),
		[]byte("{\"status\":\"unavailable\"}\n"),
		[]byte("{\"status\":\"ready\",\"extra\":true}\n"),
	} {
		if err := validateReadyResponse(raw); err == nil {
			t.Fatalf("invalid readiness response accepted: %q", raw)
		}
	}
}
