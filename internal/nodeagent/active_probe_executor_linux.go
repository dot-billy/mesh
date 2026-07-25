//go:build linux

package nodeagent

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net/netip"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"mesh/internal/runtimetelemetry"
)

type linuxActiveProbeExecutor struct {
	openSocket func() (activeProbePingSocket, error)
	entropy    io.Reader
	now        func() time.Time
}

func newPlatformActiveProbeExecutor() activeProbeExecutor {
	return newLinuxActiveProbeExecutorForTest(openLinuxActiveProbePingSocket, rand.Reader, time.Now)
}

func newLinuxActiveProbeExecutorForTest(openSocket func() (activeProbePingSocket, error), entropy io.Reader, now func() time.Time) activeProbeExecutor {
	return &linuxActiveProbeExecutor{openSocket: openSocket, entropy: entropy, now: now}
}

func (*linuxActiveProbeExecutor) Supported() bool { return true }

func (executor *linuxActiveProbeExecutor) Probe(ctx context.Context, plan activeProbePlan) runtimetelemetry.ActiveProbeResult {
	if executor == nil || executor.openSocket == nil || executor.entropy == nil || executor.now == nil || ctx == nil || !plan.localAddress.Is4() {
		return runtimetelemetry.UnavailableActiveProbe()
	}
	if len(plan.targets) == 0 {
		return runtimetelemetry.NotEligibleActiveProbe()
	}
	for _, target := range plan.targets {
		if !target.Is4() || target == plan.localAddress {
			return runtimetelemetry.UnavailableActiveProbe()
		}
	}
	if err := ctx.Err(); err != nil {
		return runtimetelemetry.UnavailableActiveProbe()
	}
	startedAt := executor.now()
	if startedAt.IsZero() {
		return runtimetelemetry.UnavailableActiveProbe()
	}
	totalDeadline := startedAt.Add(activeProbeTotalTimeout)
	socket, err := executor.openSocket()
	if err != nil {
		return activeProbeSetupFailure(err, 0)
	}
	if socket == nil {
		return runtimetelemetry.UnavailableActiveProbe()
	}
	defer socket.Close()
	if err := socket.Bind(plan.localAddress); err != nil {
		return activeProbeSetupFailure(err, activeProbeDurationMS(startedAt, executor.now()))
	}

	var attempted, replied uint64
	targetCount := min(len(plan.targets), int(runtimetelemetry.MaxActiveProbeTargets))
	for index := 0; index < targetCount; index++ {
		if ctx.Err() != nil {
			return runtimetelemetry.UnavailableActiveProbe()
		}
		now := executor.now()
		if now.IsZero() || now.Before(startedAt) || !now.Before(totalDeadline) {
			break
		}
		nonce := make([]byte, activeProbeNonceBytes)
		if _, err := io.ReadFull(executor.entropy, nonce); err != nil {
			return runtimetelemetry.UnavailableActiveProbe()
		}
		sequence := uint16(index + 1)
		request, ok := encodeActiveProbeEchoRequest(sequence, nonce)
		if !ok {
			return runtimetelemetry.UnavailableActiveProbe()
		}
		attempted++
		if err := socket.Send(plan.targets[index], request); err != nil {
			continue
		}
		deadline := now.Add(activeProbePerTargetTimeout)
		if deadline.After(totalDeadline) {
			deadline = totalDeadline
		}
		for {
			if ctx.Err() != nil {
				return runtimetelemetry.UnavailableActiveProbe()
			}
			packet, err := socket.Receive(ctx, deadline)
			if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, osDeadlineExceeded) {
				break
			}
			if err != nil {
				return runtimetelemetry.UnavailableActiveProbe()
			}
			if validActiveProbeEchoReply(packet, plan.targets[index], sequence, nonce) {
				replied++
				break
			}
			if !executor.now().Before(deadline) {
				break
			}
		}
	}
	if attempted == 0 {
		return runtimetelemetry.UnavailableActiveProbe()
	}
	age := uint64(0)
	return runtimetelemetry.ActiveProbeResult{
		Version: runtimetelemetry.ActiveProbeVersionV1, State: runtimetelemetry.ProbeAttempted,
		SampleAgeMS: &age, Attempted: attempted, Replied: replied,
		DurationMS: activeProbeDurationMS(startedAt, executor.now()),
	}
}

var osDeadlineExceeded = syscall.ETIMEDOUT

func activeProbeSetupFailure(err error, durationMS uint64) runtimetelemetry.ActiveProbeResult {
	if !errors.Is(err, syscall.EACCES) && !errors.Is(err, syscall.EPERM) {
		return runtimetelemetry.UnavailableActiveProbe()
	}
	age := uint64(0)
	return runtimetelemetry.ActiveProbeResult{
		Version: runtimetelemetry.ActiveProbeVersionV1, State: runtimetelemetry.ProbeCapabilityUnavailable,
		SampleAgeMS: &age, DurationMS: durationMS,
	}
}

func activeProbeDurationMS(startedAt, endedAt time.Time) uint64 {
	if startedAt.IsZero() || endedAt.IsZero() || endedAt.Before(startedAt) {
		return 0
	}
	duration := endedAt.Sub(startedAt)
	if duration > activeProbeTotalTimeout {
		duration = activeProbeTotalTimeout
	}
	return uint64(duration / time.Millisecond)
}

type linuxActiveProbePingSocket struct {
	fd int
}

func openLinuxActiveProbePingSocket() (activeProbePingSocket, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.IPPROTO_ICMP)
	if err != nil {
		return nil, err
	}
	return &linuxActiveProbePingSocket{fd: fd}, nil
}

func (socket *linuxActiveProbePingSocket) Bind(address netip.Addr) error {
	if socket == nil || socket.fd < 0 || !address.Is4() {
		return syscall.EINVAL
	}
	value := address.As4()
	return unix.Bind(socket.fd, &unix.SockaddrInet4{Addr: value})
}

func (socket *linuxActiveProbePingSocket) Send(target netip.Addr, packet []byte) error {
	if socket == nil || socket.fd < 0 || !target.Is4() || len(packet) > 64 {
		return syscall.EINVAL
	}
	value := target.As4()
	return unix.Sendto(socket.fd, packet, 0, &unix.SockaddrInet4{Addr: value})
}

func (socket *linuxActiveProbePingSocket) Receive(ctx context.Context, deadline time.Time) (activeProbePacket, error) {
	if socket == nil || socket.fd < 0 || ctx == nil || deadline.IsZero() {
		return activeProbePacket{}, syscall.EINVAL
	}
	buffer := make([]byte, 256)
	for {
		if err := ctx.Err(); err != nil {
			return activeProbePacket{}, err
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return activeProbePacket{}, context.DeadlineExceeded
		}
		pollFor := min(remaining, 50*time.Millisecond)
		timeoutMS := int((pollFor + time.Millisecond - 1) / time.Millisecond)
		poll := []unix.PollFd{{Fd: int32(socket.fd), Events: unix.POLLIN}}
		ready, err := unix.Poll(poll, timeoutMS)
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if err != nil {
			return activeProbePacket{}, err
		}
		if ready == 0 {
			continue
		}
		if poll[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
			return activeProbePacket{}, syscall.EIO
		}
		count, source, err := unix.Recvfrom(socket.fd, buffer, 0)
		if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EINTR) {
			continue
		}
		if err != nil {
			return activeProbePacket{}, err
		}
		address, ok := source.(*unix.SockaddrInet4)
		if !ok {
			continue
		}
		return activeProbePacket{source: netip.AddrFrom4(address.Addr), payload: append([]byte(nil), buffer[:count]...)}, nil
	}
}

func (socket *linuxActiveProbePingSocket) Close() error {
	if socket == nil || socket.fd < 0 {
		return nil
	}
	err := unix.Close(socket.fd)
	socket.fd = -1
	return err
}
