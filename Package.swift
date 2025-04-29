// swift-tools-version: 6.1
import PackageDescription

let package = Package(
    name: "WalletLibCryptoSwift",
    platforms: [
        .iOS(.v13),
        .macOS(.v10_15)
    ],
    products: [
        .library(
            name: "WalletLibCryptoSwift",
            targets: ["WalletLibCryptoSwift"]
        )
    ],
    targets: [
        .binaryTarget(
            name: "libcrypto",
            path: "Sources/OpenSSL/libcrypto.xcframework"
        ),
        .target(
            name: "WalletLibCrypto",
            dependencies: ["libcrypto"],
            path: "Sources/WalletLibCrypto",
            publicHeadersPath: "PublicHeaders",
            cSettings: [
                .headerSearchPath("PrivateHeaders")
            ]
        ),
        .target(
            name: "WalletLibCryptoSwift",
            dependencies: ["WalletLibCrypto"],
            path: "Sources/WalletLibCryptoSwift"
        ),
        .testTarget(
            name: "WalletLibCryptoTests",
            dependencies: ["WalletLibCrypto"],
            path: "WalletLibCryptoTests"
        )
    ]
)

