package iosmobile

import (
	"bytes"
	"errors"
	"io"
	"net/netip"
	"testing"
	"time"
)

func ipv4Packet(payload []byte) []byte {
	packet := make([]byte, 20+len(payload))
	packet[0] = 0x45
	packet[2] = byte(len(packet) >> 8)
	packet[3] = byte(len(packet))
	packet[8] = 64
	packet[9] = 17
	copy(packet[20:], payload)
	return packet
}

func ipv6Packet(payload []byte) []byte {
	packet := make([]byte, 40+len(payload))
	packet[0] = 0x60
	packet[4] = byte(len(payload) >> 8)
	packet[5] = byte(len(payload))
	packet[6] = 17
	packet[7] = 64
	copy(packet[40:], payload)
	return packet
}

func TestPacketFlowBridgeInjectsOneOwnedPacketIntoNebula(t *testing.T) {
	bridge, err := newPacketFlowBridge(
		[]netip.Prefix{netip.MustParsePrefix("192.0.2.7/24")},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.close()

	received := make(chan []byte, 1)
	readError := make(chan error, 1)
	go func() {
		buffer := make([]byte, maximumPacketBytes)
		count, readErr := bridge.device.Read(buffer)
		if readErr != nil {
			readError <- readErr
			return
		}
		received <- append([]byte(nil), buffer[:count]...)
	}()

	packet := ipv4Packet([]byte("apple-to-nebula"))
	expected := append([]byte(nil), packet...)
	if err := bridge.inject(packet); err != nil {
		t.Fatal(err)
	}
	clear(packet)

	select {
	case actual := <-received:
		if !bytes.Equal(actual, expected) {
			t.Fatalf("packet changed across injection: %x", actual)
		}
	case err := <-readError:
		t.Fatal(err)
	case <-time.After(time.Second):
		t.Fatal("Nebula device did not receive the injected packet")
	}
}

func TestPacketFlowBridgeReturnsOneOwnedPacketFromNebula(t *testing.T) {
	bridge, err := newPacketFlowBridge(
		[]netip.Prefix{netip.MustParsePrefix("2001:db8::7/64")},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.close()

	packet := ipv6Packet([]byte("nebula-to-apple"))
	writeResult := make(chan error, 1)
	go func() {
		written, writeErr := bridge.device.Write(packet)
		if writeErr == nil && written != len(packet) {
			writeErr = io.ErrShortWrite
		}
		writeResult <- writeErr
	}()

	actual, err := bridge.next()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actual, packet) {
		t.Fatalf("packet changed across emission: %x", actual)
	}
	clear(actual)
	select {
	case err := <-writeResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Nebula device write did not complete")
	}
}

func TestPacketFlowBridgeRejectsMalformedPacketsBeforeInjection(t *testing.T) {
	bridge, err := newPacketFlowBridge(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.close()

	for _, packet := range [][]byte{
		nil,
		{0x30},
		{0x45, 0, 0, 20},
		append(ipv4Packet(nil), 0),
		append(ipv6Packet(nil), 0),
		make([]byte, maximumPacketBytes+1),
	} {
		if err := bridge.inject(packet); err == nil {
			t.Fatalf("accepted malformed packet with %d bytes", len(packet))
		}
	}
}

func TestPacketFlowBridgeCloseUnblocksBothDirections(t *testing.T) {
	bridge, err := newPacketFlowBridge(nil)
	if err != nil {
		t.Fatal(err)
	}
	bridge.close()
	bridge.close()

	if err := bridge.inject(ipv4Packet(nil)); err == nil {
		t.Fatal("closed bridge accepted packet injection")
	}
	if _, err := bridge.next(); !errors.Is(err, io.EOF) {
		t.Fatalf("closed bridge returned %v, expected EOF", err)
	}
}
