// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "MeshTunnelContract",
    platforms: [
        .macOS(.v14),
        .iOS(.v17),
    ],
    products: [
        .library(name: "MeshTunnelContract", targets: ["MeshTunnelContract"]),
    ],
    targets: [
        .target(
            name: "MeshTunnelContract",
            path: "Shared"
        ),
        .testTarget(
            name: "MeshTunnelContractTests",
            dependencies: ["MeshTunnelContract"],
            path: "ContractTests"
        ),
    ]
)
