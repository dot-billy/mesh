//go:build linux

package nodeagent

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"syscall"

	"mesh/internal/runtimetelemetry"
)

const (
	maxRouteInterfaces = 1 << 10
	maxRouteAddresses  = 1 << 12
	maxRouteEntries    = 1 << 12
	maxRouteRIBBytes   = 4 << 20
)

type routeInterface struct {
	index     int
	up        bool
	addresses []netip.Prefix
}

type linuxRouteOverlapInspector struct {
	interfaces func() ([]routeInterface, error)
	routes     func() ([]routeInventoryEntry, error)
}

func newPlatformRouteOverlapInspector() routeOverlapInspector {
	return &linuxRouteOverlapInspector{interfaces: loadRouteInterfaces, routes: loadIPv4RouteInventory}
}

func (*linuxRouteOverlapInspector) Supported() bool { return true }

func (inspector *linuxRouteOverlapInspector) Inspect(ctx context.Context, topology verifiedRuntimeTopology) runtimetelemetry.RouteOverlapResult {
	if ctx == nil || ctx.Err() != nil || inspector == nil || inspector.interfaces == nil || inspector.routes == nil {
		return runtimetelemetry.UnavailableRouteOverlap()
	}
	interfaces, err := inspector.interfaces()
	if err != nil || ctx.Err() != nil {
		return runtimetelemetry.UnavailableRouteOverlap()
	}
	overlayInterface, ok := exactOverlayInterface(topology, interfaces)
	if !ok {
		return runtimetelemetry.UnavailableRouteOverlap()
	}
	routes, err := inspector.routes()
	if err != nil || ctx.Err() != nil {
		return runtimetelemetry.UnavailableRouteOverlap()
	}
	overlap, complete := routeInventoryOverlaps(topology.network, overlayInterface, routes)
	if !complete {
		return runtimetelemetry.UnavailableRouteOverlap()
	}
	return runtimetelemetry.ObservedRouteOverlap(overlap)
}

func exactOverlayInterface(topology verifiedRuntimeTopology, interfaces []routeInterface) (int, bool) {
	if !topology.localAddress.Is4() || !topology.network.IsValid() || topology.network != topology.network.Masked() || len(interfaces) > maxRouteInterfaces {
		return 0, false
	}
	found := 0
	addressCount := 0
	for _, candidate := range interfaces {
		if candidate.index < 1 || !candidate.up {
			continue
		}
		addressCount += len(candidate.addresses)
		if addressCount > maxRouteAddresses {
			return 0, false
		}
		for _, address := range candidate.addresses {
			if !address.IsValid() || !address.Addr().Is4() {
				continue
			}
			if address.Addr() == topology.localAddress && address.Masked() == topology.network {
				if found != 0 && found != candidate.index {
					return 0, false
				}
				found = candidate.index
			}
		}
	}
	return found, found != 0
}

func loadRouteInterfaces() ([]routeInterface, error) {
	values, err := net.Interfaces()
	if err != nil || len(values) > maxRouteInterfaces {
		return nil, errors.New("route interface inventory unavailable")
	}
	result := make([]routeInterface, 0, len(values))
	addressCount := 0
	for _, value := range values {
		addresses, err := value.Addrs()
		if err != nil {
			return nil, errors.New("route interface addresses unavailable")
		}
		addressCount += len(addresses)
		if addressCount > maxRouteAddresses {
			return nil, errors.New("route interface address limit exceeded")
		}
		projected := routeInterface{index: value.Index, up: value.Flags&net.FlagUp != 0, addresses: make([]netip.Prefix, 0, len(addresses))}
		for _, address := range addresses {
			prefix, err := netip.ParsePrefix(address.String())
			if err == nil {
				projected.addresses = append(projected.addresses, prefix)
			}
		}
		result = append(result, projected)
	}
	return result, nil
}

func loadIPv4RouteInventory() ([]routeInventoryEntry, error) {
	raw, err := syscall.NetlinkRIB(syscall.RTM_GETROUTE, syscall.AF_INET)
	if err != nil || len(raw) == 0 || len(raw) > maxRouteRIBBytes {
		return nil, errors.New("IPv4 route inventory unavailable")
	}
	messages, err := syscall.ParseNetlinkMessage(raw)
	if err != nil {
		return nil, errors.New("IPv4 route inventory is malformed")
	}
	routes := make([]routeInventoryEntry, 0, len(messages))
	for index := range messages {
		message := &messages[index]
		switch message.Header.Type {
		case syscall.NLMSG_DONE:
			continue
		case syscall.NLMSG_ERROR:
			return nil, errors.New("IPv4 route inventory returned an error")
		case syscall.RTM_NEWROUTE:
		default:
			continue
		}
		if len(message.Data) < syscall.SizeofRtMsg || message.Data[0] != syscall.AF_INET {
			return nil, errors.New("IPv4 route message is malformed")
		}
		prefixBits := int(message.Data[1])
		if prefixBits == 0 {
			// The ubiquitous default route is not a collision; any non-default
			// private/VPN/VPC route that intersects the Mesh prefix is.
			continue
		}
		if prefixBits < 0 || prefixBits > 32 {
			return nil, errors.New("IPv4 route prefix length is invalid")
		}
		attributes, err := syscall.ParseNetlinkRouteAttr(message)
		if err != nil {
			return nil, errors.New("IPv4 route attributes are malformed")
		}
		var destination netip.Addr
		interfaceIndex := 0
		destinationSeen, interfaceSeen := false, false
		for _, attribute := range attributes {
			switch attribute.Attr.Type {
			case syscall.RTA_DST:
				if destinationSeen || len(attribute.Value) != 4 {
					return nil, errors.New("IPv4 route destination is ambiguous")
				}
				destinationSeen = true
				destination = netip.AddrFrom4([4]byte(attribute.Value))
			case syscall.RTA_OIF:
				if interfaceSeen || len(attribute.Value) != 4 {
					return nil, errors.New("IPv4 route interface is ambiguous")
				}
				interfaceSeen = true
				value := binary.NativeEndian.Uint32(attribute.Value)
				maxInt := uint64(^uint(0) >> 1)
				if uint64(value) > maxInt {
					return nil, errors.New("IPv4 route interface is invalid")
				}
				interfaceIndex = int(value)
			}
		}
		if !destinationSeen || !destination.Is4() {
			return nil, errors.New("IPv4 route destination is missing")
		}
		prefix := netip.PrefixFrom(destination, prefixBits)
		if prefix != prefix.Masked() {
			return nil, errors.New("IPv4 route destination is noncanonical")
		}
		routes = append(routes, routeInventoryEntry{prefix: prefix, interfaceIndex: interfaceIndex})
		if len(routes) > maxRouteEntries {
			return nil, errors.New("IPv4 route inventory limit exceeded")
		}
	}
	return routes, nil
}
