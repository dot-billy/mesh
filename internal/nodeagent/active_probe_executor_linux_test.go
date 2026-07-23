//go:build linux

package nodeagent

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"sync"
	"syscall"
	"testing"
	"time"

	"mesh/internal/runtimetelemetry"
)

type fakeActiveProbeSend struct {
	target netip.Addr
	packet []byte
}

type fakeActiveProbeSocket struct {
	mu          sync.Mutex
	bindAddress netip.Addr
	bindErr     error
	sendErr     error
	sends       []fakeActiveProbeSend
	receive     func(context.Context, time.Time, *fakeActiveProbeSocket) (activeProbePacket, error)
	deadlines   []time.Time
	closed      bool
}

func (socket *fakeActiveProbeSocket) Bind(address netip.Addr) error {
	socket.mu.Lock()
	defer socket.mu.Unlock()
	socket.bindAddress = address
	return socket.bindErr
}

func (socket *fakeActiveProbeSocket) Send(target netip.Addr, packet []byte) error {
	socket.mu.Lock()
	socket.sends = append(socket.sends, fakeActiveProbeSend{target: target, packet: bytes.Clone(packet)})
	err := socket.sendErr
	socket.mu.Unlock()
	return err
}

func (socket *fakeActiveProbeSocket) Receive(ctx context.Context, deadline time.Time) (activeProbePacket, error) {
	socket.mu.Lock()
	socket.deadlines = append(socket.deadlines, deadline)
	receive := socket.receive
	socket.mu.Unlock()
	if receive == nil {
		return activeProbePacket{}, context.DeadlineExceeded
	}
	return receive(ctx, deadline, socket)
}

func (socket *fakeActiveProbeSocket) Close() error {
	socket.mu.Lock()
	socket.closed = true
	socket.mu.Unlock()
	return nil
}

func deterministicProbeEntropy() io.Reader {
	value := make([]byte, 16*runtimetelemetry.MaxActiveProbeTargets)
	for index := range value {
		value[index] = byte(index + 1)
	}
	return bytes.NewReader(value)
}

func activeProbeTestPlan(targets ...string) activeProbePlan {
	plan := activeProbePlan{localAddress: netip.MustParseAddr("10.42.0.9")}
	for _, target := range targets {
		plan.targets = append(plan.targets, netip.MustParseAddr(target))
	}
	return plan
}

func activeProbeReplyFromRequest(request []byte) []byte {
	reply := bytes.Clone(request)
	reply[0] = 0
	reply[2], reply[3] = 0, 0
	binary.BigEndian.PutUint16(reply[2:4], testICMPChecksum(reply))
	return reply
}

func testICMPChecksum(packet []byte) uint16 {
	var sum uint32
	for index := 0; index+1 < len(packet); index += 2 {
		sum += uint32(binary.BigEndian.Uint16(packet[index : index+2]))
	}
	if len(packet)%2 != 0 {
		sum += uint32(packet[len(packet)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func TestLinuxActiveProbeAcceptsOnlyExactRepliesOnOneBoundSocket(t *testing.T) {
	targetOne := netip.MustParseAddr("10.42.0.1")
	targetTwo := netip.MustParseAddr("10.42.0.2")
	socket := &fakeActiveProbeSocket{}
	receiveCalls := 0
	socket.receive = func(_ context.Context, _ time.Time, current *fakeActiveProbeSocket) (activeProbePacket, error) {
		current.mu.Lock()
		sends := append([]fakeActiveProbeSend(nil), current.sends...)
		current.mu.Unlock()
		receiveCalls++
		switch receiveCalls {
		case 1:
			return activeProbePacket{source: targetTwo, payload: activeProbeReplyFromRequest(sends[0].packet)}, nil
		case 2:
			wrongNonce := activeProbeReplyFromRequest(sends[0].packet)
			wrongNonce[len(wrongNonce)-1] ^= 0xff
			wrongNonce[2], wrongNonce[3] = 0, 0
			binary.BigEndian.PutUint16(wrongNonce[2:4], testICMPChecksum(wrongNonce))
			return activeProbePacket{source: targetOne, payload: wrongNonce}, nil
		case 3:
			return activeProbePacket{source: targetOne, payload: activeProbeReplyFromRequest(sends[0].packet)}, nil
		case 4:
			return activeProbePacket{source: targetOne, payload: activeProbeReplyFromRequest(sends[0].packet)}, nil
		case 5:
			return activeProbePacket{source: targetTwo, payload: activeProbeReplyFromRequest(sends[1].packet)}, nil
		default:
			return activeProbePacket{}, context.DeadlineExceeded
		}
	}
	openCalls := 0
	executor := newLinuxActiveProbeExecutorForTest(func() (activeProbePingSocket, error) {
		openCalls++
		return socket, nil
	}, deterministicProbeEntropy(), time.Now)
	result := executor.Probe(context.Background(), activeProbeTestPlan(targetOne.String(), targetTwo.String()))
	if result.State != runtimetelemetry.ProbeAttempted || result.Attempted != 2 || result.Replied != 2 || result.SampleAgeMS == nil || *result.SampleAgeMS != 0 {
		t.Fatalf("probe result = %#v", result)
	}
	if openCalls != 1 || socket.bindAddress != netip.MustParseAddr("10.42.0.9") || !socket.closed || len(socket.sends) != 2 {
		t.Fatalf("socket open=%d bind=%s closed=%t sends=%d", openCalls, socket.bindAddress, socket.closed, len(socket.sends))
	}
	if len(socket.sends[0].packet) > 64 || len(socket.sends[0].packet) < 24 || testICMPChecksum(socket.sends[0].packet) != 0 {
		t.Fatalf("invalid request packet: %x", socket.sends[0].packet)
	}
	if binary.BigEndian.Uint16(socket.sends[0].packet[6:8]) == binary.BigEndian.Uint16(socket.sends[1].packet[6:8]) ||
		bytes.Equal(socket.sends[0].packet[len(socket.sends[0].packet)-16:], socket.sends[1].packet[len(socket.sends[1].packet)-16:]) {
		t.Fatal("probe requests reused a sequence or nonce")
	}
	for _, deadline := range socket.deadlines {
		if deadline.IsZero() || deadline.After(time.Now().Add(activeProbePerTargetTimeout+100*time.Millisecond)) {
			t.Fatalf("unbounded receive deadline: %s", deadline)
		}
	}
}

func TestLinuxActiveProbeRejectsMalformedWrongAndLateReplies(t *testing.T) {
	target := netip.MustParseAddr("10.42.0.1")
	tests := map[string]func([]byte) activeProbePacket{
		"malformed": func(request []byte) activeProbePacket {
			return activeProbePacket{source: target, payload: request[:7]}
		},
		"request type": func(request []byte) activeProbePacket {
			return activeProbePacket{source: target, payload: request}
		},
		"wrong code": func(request []byte) activeProbePacket {
			reply := activeProbeReplyFromRequest(request)
			reply[1] = 1
			return activeProbePacket{source: target, payload: reply}
		},
		"wrong sequence": func(request []byte) activeProbePacket {
			reply := activeProbeReplyFromRequest(request)
			binary.BigEndian.PutUint16(reply[6:8], binary.BigEndian.Uint16(reply[6:8])+1)
			return activeProbePacket{source: target, payload: reply}
		},
		"wrong checksum": func(request []byte) activeProbePacket {
			reply := activeProbeReplyFromRequest(request)
			reply[2] ^= 0xff
			return activeProbePacket{source: target, payload: reply}
		},
	}
	for name, packet := range tests {
		t.Run(name, func(t *testing.T) {
			socket := &fakeActiveProbeSocket{}
			delivered := false
			socket.receive = func(_ context.Context, _ time.Time, current *fakeActiveProbeSocket) (activeProbePacket, error) {
				if delivered {
					return activeProbePacket{}, context.DeadlineExceeded
				}
				delivered = true
				return packet(current.sends[0].packet), nil
			}
			executor := newLinuxActiveProbeExecutorForTest(func() (activeProbePingSocket, error) { return socket, nil }, deterministicProbeEntropy(), time.Now)
			result := executor.Probe(context.Background(), activeProbeTestPlan(target.String()))
			if result.State != runtimetelemetry.ProbeAttempted || result.Attempted != 1 || result.Replied != 0 {
				t.Fatalf("rejected reply result = %#v", result)
			}
		})
	}
}

func TestLinuxActiveProbeCapsTargetsAndCountsSendErrors(t *testing.T) {
	socket := &fakeActiveProbeSocket{sendErr: syscall.ENETUNREACH}
	targets := []string{"10.42.0.1", "10.42.0.2", "10.42.0.3", "10.42.0.4", "10.42.0.5", "10.42.0.6", "10.42.0.7", "10.42.0.8", "10.42.0.10"}
	executor := newLinuxActiveProbeExecutorForTest(func() (activeProbePingSocket, error) { return socket, nil }, deterministicProbeEntropy(), time.Now)
	result := executor.Probe(context.Background(), activeProbeTestPlan(targets...))
	if result.State != runtimetelemetry.ProbeAttempted || result.Attempted != 8 || result.Replied != 0 || len(socket.sends) != 8 {
		t.Fatalf("bounded send-error result = %#v sends=%d", result, len(socket.sends))
	}
}

func TestLinuxActiveProbeClassifiesSocketAndEntropyFailures(t *testing.T) {
	for _, test := range []struct {
		name      string
		openError error
		bindError error
		want      runtimetelemetry.ActiveProbeState
	}{
		{name: "open permission", openError: syscall.EPERM, want: runtimetelemetry.ProbeCapabilityUnavailable},
		{name: "open access", openError: syscall.EACCES, want: runtimetelemetry.ProbeCapabilityUnavailable},
		{name: "bind permission", bindError: syscall.EPERM, want: runtimetelemetry.ProbeCapabilityUnavailable},
		{name: "other setup", openError: syscall.ENOMEM, want: runtimetelemetry.ProbeUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			socket := &fakeActiveProbeSocket{bindErr: test.bindError}
			executor := newLinuxActiveProbeExecutorForTest(func() (activeProbePingSocket, error) { return socket, test.openError }, deterministicProbeEntropy(), time.Now)
			result := executor.Probe(context.Background(), activeProbeTestPlan("10.42.0.1"))
			if result.State != test.want || result.Attempted != 0 || result.Replied != 0 ||
				(test.want == runtimetelemetry.ProbeCapabilityUnavailable) != (result.SampleAgeMS != nil) {
				t.Fatalf("failure result = %#v", result)
			}
		})
	}

	socket := &fakeActiveProbeSocket{}
	executor := newLinuxActiveProbeExecutorForTest(func() (activeProbePingSocket, error) { return socket, nil }, errorReader{}, time.Now)
	result := executor.Probe(context.Background(), activeProbeTestPlan("10.42.0.1"))
	if result != runtimetelemetry.UnavailableActiveProbe() || len(socket.sends) != 0 || !socket.closed {
		t.Fatalf("entropy failure result = %#v sends=%d closed=%t", result, len(socket.sends), socket.closed)
	}
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, errors.New("entropy unavailable") }

func TestLinuxActiveProbeHonorsCancellationPromptly(t *testing.T) {
	socket := &fakeActiveProbeSocket{}
	entered := make(chan struct{})
	socket.receive = func(ctx context.Context, _ time.Time, _ *fakeActiveProbeSocket) (activeProbePacket, error) {
		close(entered)
		<-ctx.Done()
		return activeProbePacket{}, ctx.Err()
	}
	executor := newLinuxActiveProbeExecutorForTest(func() (activeProbePingSocket, error) { return socket, nil }, deterministicProbeEntropy(), time.Now)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan runtimetelemetry.ActiveProbeResult, 1)
	go func() { done <- executor.Probe(ctx, activeProbeTestPlan("10.42.0.1")) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("probe did not enter receive")
	}
	cancel()
	select {
	case result := <-done:
		if result != runtimetelemetry.UnavailableActiveProbe() || !socket.closed {
			t.Fatalf("canceled result = %#v closed=%t", result, socket.closed)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("probe did not honor cancellation promptly")
	}
}

func TestLinuxActiveProbeReturnsNotEligibleWithoutOpeningSocket(t *testing.T) {
	openCalls := 0
	executor := newLinuxActiveProbeExecutorForTest(func() (activeProbePingSocket, error) {
		openCalls++
		return nil, errors.New("must not open")
	}, deterministicProbeEntropy(), time.Now)
	result := executor.Probe(context.Background(), activeProbeTestPlan())
	if result.State != runtimetelemetry.ProbeNotEligible || openCalls != 0 {
		t.Fatalf("empty-plan result = %#v opens=%d", result, openCalls)
	}
}
