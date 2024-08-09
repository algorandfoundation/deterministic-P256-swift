// swift-tools-version: 5.9
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "deterministicP256-swift",
    platforms: [
        .iOS(.v15),
        .watchOS(.v9),
        .macOS(.v12),
    ],
    products: [
        .library(
            name: "deterministicP256-swift",
            targets: ["deterministicP256-swift"]
        ),
    ],
    dependencies: [
        .package(url: "https://github.com/Electric-Coin-Company/MnemonicSwift.git", from: "2.2.4"),
        .package(url: "https://github.com/nicklockwood/SwiftFormat", from: "0.53.9"),
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "deterministicP256-swift",
            dependencies:
            [
                .product(name: "MnemonicSwift", package: "MnemonicSwift"),
            ]
        ),
        .testTarget(
            name: "deterministicP256-swiftTests",
            dependencies: [
                "deterministicP256-swift",
                .product(name: "MnemonicSwift", package: "MnemonicSwift"),
            ]
        ),
    ]
)
