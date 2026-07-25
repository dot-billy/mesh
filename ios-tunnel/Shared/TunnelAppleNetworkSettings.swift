import Foundation
import NetworkExtension

public enum TunnelAppleNetworkSettingsFactory {
  public static func make(
    plan: TunnelNetworkSettingsPlan,
    tunnelRemoteAddress: TunnelRemoteAddress
  ) throws -> NEPacketTunnelNetworkSettings {
    try plan.validate()
    let settings = NEPacketTunnelNetworkSettings(
      tunnelRemoteAddress: tunnelRemoteAddress.value
    )
    settings.mtu = NSNumber(value: plan.mtu)

    let ipv4Addresses = try plan.addresses.filter {
      try family(of: $0.address) == AF_INET
    }
    if !ipv4Addresses.isEmpty {
      let ipv4 = NEIPv4Settings(
        addresses: ipv4Addresses.map(\.address),
        subnetMasks: ipv4Addresses.map {
          ipv4Mask(prefixLength: $0.prefixLength)
        }
      )
      ipv4.includedRoutes = try ipv4Routes(plan.includedRoutes)
      ipv4.excludedRoutes = try ipv4Routes(plan.excludedRoutes)
      settings.ipv4Settings = ipv4
    }

    let ipv6Addresses = try plan.addresses.filter {
      try family(of: $0.address) == AF_INET6
    }
    if !ipv6Addresses.isEmpty {
      let ipv6 = NEIPv6Settings(
        addresses: ipv6Addresses.map(\.address),
        networkPrefixLengths: ipv6Addresses.map {
          NSNumber(value: $0.prefixLength)
        }
      )
      ipv6.includedRoutes = try ipv6Routes(plan.includedRoutes)
      ipv6.excludedRoutes = try ipv6Routes(plan.excludedRoutes)
      settings.ipv6Settings = ipv6
    }

    if !plan.dnsServers.isEmpty {
      settings.dnsSettings = NEDNSSettings(servers: plan.dnsServers)
    }
    return settings
  }

  private static func ipv4Routes(
    _ routes: [TunnelIPPrefix]
  ) throws -> [NEIPv4Route] {
    try routes.compactMap { route in
      guard try family(of: route.address) == AF_INET else {
        return nil
      }
      return NEIPv4Route(
        destinationAddress: route.address,
        subnetMask: ipv4Mask(prefixLength: route.prefixLength)
      )
    }
  }

  private static func ipv6Routes(
    _ routes: [TunnelIPPrefix]
  ) throws -> [NEIPv6Route] {
    try routes.compactMap { route in
      guard try family(of: route.address) == AF_INET6 else {
        return nil
      }
      return NEIPv6Route(
        destinationAddress: route.address,
        networkPrefixLength: NSNumber(value: route.prefixLength)
      )
    }
  }

  private static func family(of address: String) throws -> Int32 {
    try ParsedIPAddress.parse(
      address,
      field: "networkSettings.address"
    ).family
  }

  private static func ipv4Mask(prefixLength: UInt8) -> String {
    let prefix = Int(prefixLength)
    return (0..<4).map { index in
      let bits = min(max(prefix - index * 8, 0), 8)
      return String(bits == 0 ? 0 : 256 - (1 << (8 - bits)))
    }.joined(separator: ".")
  }
}
