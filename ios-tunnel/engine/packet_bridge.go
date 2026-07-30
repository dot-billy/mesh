package iosmobile

import (
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"os"
	"sync"

	"github.com/slackhq/nebula/overlay"
	"github.com/slackhq/nebula/routing"
)

const maximumPacketBytes = 65_575

// packetFlowBridge is the source-only adapter between Apple's documented
// packet callbacks and Nebula's exported in-memory UserDevice. It deliberately
// remains unexported from the gomobile surface until a physical-device
// feasibility review approves the lifecycle and backpressure contract.
type packetFlowBridge struct {
	device     *callbackDevice
	fromEngine *io.PipeReader
	toEngine   *io.PipeWriter
	closeOnce  sync.Once
}

func newPacketFlowBridge(
	vpnNetworks []netip.Prefix,
) (*packetFlowBridge, error) {
	rawDevice, err := overlay.NewUserDevice(vpnNetworks)
	if err != nil {
		return nil, errors.New("create Nebula user device")
	}
	device, ok := rawDevice.(*overlay.UserDevice)
	if !ok {
		_ = rawDevice.Close()
		return nil, errors.New("Nebula user device type is invalid")
	}
	fromEngine, toEngine := device.Pipe()
	return &packetFlowBridge{
		device:     &callbackDevice{UserDevice: device},
		fromEngine: fromEngine,
		toEngine:   toEngine,
	}, nil
}

// callbackDevice adapts UserDevice shutdown to the contract expected by
// Nebula's production interface loop. UserDevice returns io.ErrClosedPipe,
// while that loop recognizes os.ErrClosed as intentional shutdown.
type callbackDevice struct {
	*overlay.UserDevice
	closeOnce sync.Once
}

func (d *callbackDevice) Read(packet []byte) (int, error) {
	count, err := d.UserDevice.Read(packet)
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) {
		return count, os.ErrClosed
	}
	return count, err
}

func (d *callbackDevice) Write(packet []byte) (int, error) {
	count, err := d.UserDevice.Write(packet)
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) {
		return count, os.ErrClosed
	}
	return count, err
}

func (d *callbackDevice) Close() error {
	d.closeOnce.Do(func() {
		_ = d.UserDevice.Close()
	})
	return nil
}

func (d *callbackDevice) Name() string {
	return "mesh-ios-packet-flow"
}

func (d *callbackDevice) SupportsMultiqueue() bool {
	return false
}

func (d *callbackDevice) NewMultiQueueReader() (io.ReadWriteCloser, error) {
	return nil, errors.New("callback device does not support multiqueue")
}

func (d *callbackDevice) RoutesFor(ip netip.Addr) routing.Gateways {
	return d.UserDevice.RoutesFor(ip)
}

// inject copies one complete Apple packet before handing it to Nebula.
func (b *packetFlowBridge) inject(packet []byte) error {
	owned, err := validateAndCopyPacket(packet)
	if err != nil {
		return err
	}
	written, err := b.toEngine.Write(owned)
	clear(owned)
	if err != nil {
		return errors.New("inject packet into Nebula")
	}
	if written != len(packet) {
		return errors.New("Nebula packet injection was incomplete")
	}
	return nil
}

// next returns one complete packet emitted by Nebula in newly owned memory.
func (b *packetFlowBridge) next() ([]byte, error) {
	buffer := make([]byte, maximumPacketBytes)
	count, err := b.fromEngine.Read(buffer)
	if err != nil {
		clear(buffer)
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) {
			return nil, io.EOF
		}
		return nil, errors.New("read packet from Nebula")
	}
	packet, err := validateAndCopyPacket(buffer[:count])
	clear(buffer)
	if err != nil {
		return nil, errors.New("Nebula emitted an invalid packet")
	}
	return packet, nil
}

func (b *packetFlowBridge) close() {
	b.closeOnce.Do(func() {
		_ = b.device.Close()
	})
}

func validateAndCopyPacket(packet []byte) ([]byte, error) {
	if len(packet) == 0 || len(packet) > maximumPacketBytes {
		return nil, errors.New("packet size is invalid")
	}
	switch packet[0] >> 4 {
	case 4:
		if len(packet) < 20 {
			return nil, errors.New("IPv4 packet is truncated")
		}
		headerBytes := int(packet[0]&0x0f) * 4
		totalBytes := int(binary.BigEndian.Uint16(packet[2:4]))
		if headerBytes < 20 ||
			headerBytes > len(packet) ||
			totalBytes != len(packet) {
			return nil, errors.New("IPv4 packet lengths are invalid")
		}
	case 6:
		if len(packet) < 40 {
			return nil, errors.New("IPv6 packet is truncated")
		}
		totalBytes := 40 + int(binary.BigEndian.Uint16(packet[4:6]))
		if totalBytes != len(packet) {
			return nil, errors.New("IPv6 packet length is invalid")
		}
	default:
		return nil, errors.New("packet IP version is invalid")
	}
	return append([]byte(nil), packet...), nil
}
