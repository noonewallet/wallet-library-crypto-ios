// swift-tools-version:5.7
import PackageDescription

let package = Package(
    name: "WalletLibCrypto",
    platforms: [
        .iOS(.v13),
        .macOS(.v10_15)
    ],
    products: [
        .library(
            name: "WalletLibCrypto",
            targets: ["WalletLibCrypto"]
        )
    ],
    targets: [
        .target(
            name: "WalletLibCrypto",
            path: "WalletLibCrypto",
            cSettings: [
                .headerSearchPath("PrivateHeaders"),
                .headerSearchPath("OpenSSL")         
            ]
        ),
        .testTarget(
            name: "WalletLibCryptoTests",
            dependencies: ["WalletLibCrypto"],
            path: "WalletLibCryptoTests"
        )
    ]
)

