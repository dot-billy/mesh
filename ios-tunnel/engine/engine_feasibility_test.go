package iosmobile

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"
)

type feasibilityEngine struct {
	session *EngineSession
	vpnAddr netip.Addr
	udpPort int
	cert    cert.Certificate
}

func TestPinnedNebulaEngineUsesCallbackPacketsOverRealUDP(t *testing.T) {
	now := time.Now().UTC().Round(time.Second)
	authority := newEngineTestAuthority(t, now)
	lighthouseAddr := netip.MustParseAddr("10.88.0.1")
	memberAddr := netip.MustParseAddr("10.88.0.2")
	lighthousePort := reserveUDPPort(t)
	memberPort := reserveUDPPort(t)
	for memberPort == lighthousePort {
		memberPort = reserveUDPPort(t)
	}

	lighthouse := newFeasibilityEngine(
		t,
		authority,
		now,
		"callback-lighthouse",
		lighthouseAddr,
		lighthousePort,
		true,
		netip.AddrPort{},
	)
	member := newFeasibilityEngine(
		t,
		authority,
		now,
		"callback-member",
		memberAddr,
		memberPort,
		false,
		netip.AddrPortFrom(
			netip.MustParseAddr("127.0.0.1"),
			uint16(lighthousePort),
		),
	)
	if err := lighthouse.session.Start(); err != nil {
		t.Fatal(err)
	}
	if err := member.session.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stopFeasibilityEngine(member)
		stopFeasibilityEngine(lighthouse)
	})

	request := icmpv4Packet(
		memberAddr,
		lighthouseAddr,
		8,
		[]byte("mesh-nebula-callback-request"),
	)
	if err := member.session.Send(request); err != nil {
		t.Fatal(err)
	}
	actualRequest := awaitEnginePacket(t, lighthouse.session)
	if !bytes.Equal(actualRequest, request) {
		t.Fatalf("authenticated request changed: %x", actualRequest)
	}

	memberFingerprint, err := member.cert.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	observedMember := lighthouse.session.control.GetCertByVpnIp(memberAddr)
	if observedMember == nil {
		t.Fatal("lighthouse did not authenticate the member certificate")
	}
	observedFingerprint, err := observedMember.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	if observedFingerprint != memberFingerprint {
		t.Fatalf(
			"authenticated member fingerprint %s, expected %s",
			observedFingerprint,
			memberFingerprint,
		)
	}

	reply := icmpv4Packet(
		lighthouseAddr,
		memberAddr,
		0,
		[]byte("mesh-nebula-callback-reply"),
	)
	if err := lighthouse.session.Send(reply); err != nil {
		t.Fatal(err)
	}
	actualReply := awaitEnginePacket(t, member.session)
	if !bytes.Equal(actualReply, reply) {
		t.Fatalf("authenticated reply changed: %x", actualReply)
	}

	host := member.session.control.GetHostInfoByVpnAddr(lighthouseAddr, false)
	if host == nil {
		t.Fatal("member has no authenticated lighthouse tunnel")
	}
	if !host.CurrentRemote.Addr().IsLoopback() ||
		host.CurrentRemote.Port() != uint16(lighthousePort) {
		t.Fatalf("unexpected direct UDP remote: %s", host.CurrentRemote)
	}
	if len(host.CurrentRelaysToMe) != 0 ||
		len(host.CurrentRelaysThroughMe) != 0 {
		t.Fatal("direct callback proof unexpectedly used a relay")
	}

	if err := member.session.Rebind(); err != nil {
		t.Fatal(err)
	}
	reboundRequest := icmpv4Packet(
		memberAddr,
		lighthouseAddr,
		8,
		[]byte("mesh-nebula-callback-after-rebind"),
	)
	if err := member.session.Send(reboundRequest); err != nil {
		t.Fatal(err)
	}
	actualReboundRequest := awaitEnginePacket(t, lighthouse.session)
	if !bytes.Equal(actualReboundRequest, reboundRequest) {
		t.Fatalf(
			"authenticated packet changed after UDP rebind: %x",
			actualReboundRequest,
		)
	}
}

func newFeasibilityEngine(
	t *testing.T,
	authority engineTestAuthority,
	now time.Time,
	name string,
	vpnAddr netip.Addr,
	udpPort int,
	amLighthouse bool,
	lighthouseRemote netip.AddrPort,
) *feasibilityEngine {
	t.Helper()
	fixture := newEngineTestFixture(
		t,
		authority,
		now,
		name,
		vpnAddr,
		udpPort,
		amLighthouse,
		lighthouseRemote,
	)
	session := newEngineTestSession(fixture.privateKey)
	if err := session.Prepare(fixture.raw); err != nil {
		t.Fatal(err)
	}
	return &feasibilityEngine{
		session: session,
		vpnAddr: vpnAddr,
		udpPort: udpPort,
		cert:    fixture.certificate,
	}
}

func reserveUDPPort(t *testing.T) int {
	t.Helper()
	socket, err := net.ListenUDP(
		"udp4",
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)},
	)
	if err != nil {
		t.Fatal(err)
	}
	port := socket.LocalAddr().(*net.UDPAddr).Port
	if err := socket.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

func awaitEnginePacket(t *testing.T, session *EngineSession) []byte {
	t.Helper()
	type result struct {
		packet []byte
		err    error
	}
	completed := make(chan result, 1)
	go func() {
		packet, err := session.Receive()
		completed <- result{packet: packet, err: err}
	}()
	select {
	case value := <-completed:
		if value.err != nil {
			t.Fatal(value.err)
		}
		return value.packet
	case <-time.After(8 * time.Second):
		t.Fatal("timed out waiting for an authenticated callback packet")
		return nil
	}
}

func stopFeasibilityEngine(engine *feasibilityEngine) {
	if engine == nil || engine.session == nil {
		return
	}
	engine.session.Stop()
}

func icmpv4Packet(
	source netip.Addr,
	destination netip.Addr,
	icmpType byte,
	payload []byte,
) []byte {
	if !source.Is4() || !destination.Is4() {
		panic("ICMP feasibility packet requires IPv4")
	}
	packet := make([]byte, 20+8+len(payload))
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[4] = 0x20
	packet[5] = 0x26
	packet[8] = 64
	packet[9] = 1
	copy(packet[12:16], source.AsSlice())
	copy(packet[16:20], destination.AsSlice())
	binary.BigEndian.PutUint16(packet[10:12], internetChecksum(packet[:20]))
	packet[20] = icmpType
	packet[21] = 0
	packet[24] = 0x12
	packet[25] = 0x34
	packet[27] = 1
	copy(packet[28:], payload)
	binary.BigEndian.PutUint16(packet[22:24], internetChecksum(packet[20:]))
	return packet
}

func internetChecksum(data []byte) uint16 {
	var sum uint32
	for len(data) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(data[:2]))
		data = data[2:]
	}
	if len(data) == 1 {
		sum += uint32(data[0]) << 8
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func (e *feasibilityEngine) String() string {
	return fmt.Sprintf("%s@127.0.0.1:%d", e.vpnAddr, e.udpPort)
}
