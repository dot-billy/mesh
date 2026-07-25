//go:build linux

package main

import (
	"encoding/binary"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
)

func testIPv4ICMPPacket(source, target netip.Addr, icmpType, code byte) []byte {
	packet := make([]byte, 28)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8] = 64
	packet[9] = 1
	sourceBytes := source.As4()
	targetBytes := target.As4()
	copy(packet[12:16], sourceBytes[:])
	copy(packet[16:20], targetBytes[:])
	packet[20] = icmpType
	packet[21] = code
	return packet
}

func TestExactEchoRequestRejectsOtherTunTraffic(t *testing.T) {
	source := netip.MustParseAddr("10.88.0.2")
	target := netip.MustParseAddr("10.88.0.1")
	if !exactEchoRequest(testIPv4ICMPPacket(source, target, 8, 0), source, target) {
		t.Fatal("exact ICMP echo request was not recognized")
	}
	tests := map[string][]byte{
		"truncated":        {0x45},
		"IPv6":             append([]byte{0x60}, make([]byte, 39)...),
		"wrong source":     testIPv4ICMPPacket(netip.MustParseAddr("10.88.0.3"), target, 8, 0),
		"wrong target":     testIPv4ICMPPacket(source, netip.MustParseAddr("10.88.0.4"), 8, 0),
		"reply":            testIPv4ICMPPacket(source, target, 0, 0),
		"nonzero code":     testIPv4ICMPPacket(source, target, 8, 1),
		"other protocol":   testIPv4ICMPPacket(source, target, 8, 0),
		"fragmented":       testIPv4ICMPPacket(source, target, 8, 0),
		"invalid IHL":      testIPv4ICMPPacket(source, target, 8, 0),
		"truncated length": testIPv4ICMPPacket(source, target, 8, 0),
	}
	tests["other protocol"][9] = 17
	binary.BigEndian.PutUint16(tests["fragmented"][6:8], 0x2000)
	tests["invalid IHL"][0] = 0x44
	binary.BigEndian.PutUint16(tests["truncated length"][2:4], 100)
	for name, packet := range tests {
		t.Run(name, func(t *testing.T) {
			if exactEchoRequest(packet, source, target) {
				t.Fatal("unrelated packet was counted")
			}
		})
	}
}

func TestParseCaptureTargetsRequiresUniqueBoundedIPv4Set(t *testing.T) {
	source := netip.MustParseAddr("10.88.0.2")
	targets, err := parseCaptureTargets(source, []string{"10.88.0.10", "10.88.0.11"})
	if err != nil || len(targets) != 2 || targets[0].String() != "10.88.0.10" || targets[1].String() != "10.88.0.11" {
		t.Fatalf("targets=%v err=%v", targets, err)
	}
	for name, raw := range map[string][]string{
		"missing":   nil,
		"source":    {source.String()},
		"duplicate": {"10.88.0.10", "10.88.0.10"},
		"ipv6":      {"2001:db8::1"},
		"too many":  {"10.88.0.1", "10.88.0.2", "10.88.0.3", "10.88.0.4", "10.88.0.5", "10.88.0.6", "10.88.0.7", "10.88.0.8", "10.88.0.9"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseCaptureTargets(source, raw); err == nil {
				t.Fatal("invalid capture target set was accepted")
			}
		})
	}
}

func TestParseTelemetryArgumentsRequiresExactPrivateInputs(t *testing.T) {
	directory := t.TempDir()
	valid := []string{
		"--state", filepath.Join(directory, "state.json"),
		"--nebula", "/opt/mesh/nebula",
		"--nebula-cert", "/opt/mesh/nebula-cert",
	}
	configuration, err := parseTelemetryArguments(valid)
	if err != nil {
		t.Fatalf("parse valid telemetry arguments: %v", err)
	}
	if configuration.statePath != valid[1] || configuration.nebulaBinary != valid[3] || configuration.nebulaCertBinary != valid[5] {
		t.Fatalf("telemetry configuration = %#v", configuration)
	}
	for name, arguments := range map[string][]string{
		"missing state":        {"--nebula", "/opt/mesh/nebula", "--nebula-cert", "/opt/mesh/nebula-cert"},
		"relative state":       {"--state", "state.json", "--nebula", "/opt/mesh/nebula", "--nebula-cert", "/opt/mesh/nebula-cert"},
		"relative nebula":      {"--state", valid[1], "--nebula", "nebula", "--nebula-cert", "/opt/mesh/nebula-cert"},
		"relative cert binary": {"--state", valid[1], "--nebula", "/opt/mesh/nebula", "--nebula-cert", "nebula-cert"},
		"extra argument":       append(append([]string{}, valid...), "unexpected"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseTelemetryArguments(arguments); err == nil {
				t.Fatal("unsafe telemetry arguments were accepted")
			}
		})
	}
}

func TestRequireEmptyCapabilitiesChecksEffectiveAndBoundingSets(t *testing.T) {
	valid := strings.Join([]string{
		"Name:\tprobecapture",
		"CapInh:\t0000000000000000",
		"CapPrm:\t0000000000000000",
		"CapEff:\t0000000000000000",
		"CapBnd:\t0000000000000000",
		"CapAmb:\t0000000000000000",
	}, "\n") + "\n"
	if err := requireEmptyCapabilities([]byte(valid)); err != nil {
		t.Fatalf("zero capabilities rejected: %v", err)
	}
	for name, status := range map[string]string{
		"effective": strings.Replace(valid, "CapEff:\t0000000000000000", "CapEff:\t0000000000002000", 1),
		"bounding":  strings.Replace(valid, "CapBnd:\t0000000000000000", "CapBnd:\t000001ffffffffff", 1),
		"missing":   strings.Replace(valid, "CapEff:\t0000000000000000\n", "", 1),
		"duplicate": valid + "CapBnd:\t0000000000000000\n",
	} {
		t.Run(name, func(t *testing.T) {
			if err := requireEmptyCapabilities([]byte(status)); err == nil {
				t.Fatal("unsafe capability status was accepted")
			}
		})
	}
}
