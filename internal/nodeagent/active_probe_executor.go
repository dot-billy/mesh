package nodeagent

import (
	"context"
	"encoding/binary"
	"net/netip"
	"time"

	"mesh/internal/runtimetelemetry"
)

const (
	activeProbePerTargetTimeout = 750 * time.Millisecond
	activeProbeTotalTimeout     = 6 * time.Second
	activeProbeNonceBytes       = 16
	activeProbePacketBytes      = 32
)

var activeProbePayloadMagic = [8]byte{'M', 'S', 'H', 'P', 'R', 'B', '0', '1'}

type activeProbeExecutor interface {
	Supported() bool
	Probe(context.Context, activeProbePlan) runtimetelemetry.ActiveProbeResult
}

type activeProbePacket struct {
	source  netip.Addr
	payload []byte
}

type activeProbePingSocket interface {
	Bind(netip.Addr) error
	Send(netip.Addr, []byte) error
	Receive(context.Context, time.Time) (activeProbePacket, error)
	Close() error
}

func encodeActiveProbeEchoRequest(sequence uint16, nonce []byte) ([]byte, bool) {
	if sequence == 0 || len(nonce) != activeProbeNonceBytes {
		return nil, false
	}
	packet := make([]byte, activeProbePacketBytes)
	packet[0] = 8
	packet[1] = 0
	binary.BigEndian.PutUint16(packet[6:8], sequence)
	copy(packet[8:16], activeProbePayloadMagic[:])
	copy(packet[16:], nonce)
	binary.BigEndian.PutUint16(packet[2:4], activeProbeICMPChecksum(packet))
	return packet, true
}

func validActiveProbeEchoReply(packet activeProbePacket, target netip.Addr, sequence uint16, nonce []byte) bool {
	if packet.source != target || len(packet.payload) != activeProbePacketBytes || len(nonce) != activeProbeNonceBytes ||
		packet.payload[0] != 0 || packet.payload[1] != 0 || activeProbeICMPChecksum(packet.payload) != 0 ||
		binary.BigEndian.Uint16(packet.payload[6:8]) != sequence {
		return false
	}
	for index := range activeProbePayloadMagic {
		if packet.payload[8+index] != activeProbePayloadMagic[index] {
			return false
		}
	}
	for index := range nonce {
		if packet.payload[16+index] != nonce[index] {
			return false
		}
	}
	return true
}

func activeProbeICMPChecksum(packet []byte) uint16 {
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
