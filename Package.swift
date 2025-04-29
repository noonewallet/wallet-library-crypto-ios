// swift-tools-version: 6.1
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
        .binaryTarget(
            name: "libcrypto",
            path: "WalletLibCrypto/OpenSSL/libcrypto.xcframework"
        ),
        .target(
            name: "WalletLibCryptoC",
            dependencies: ["libcrypto"],
            path: "WalletLibCrypto",
            publicHeadersPath: "PrivateHeaders",
            cSettings: [
                .headerSearchPath("PrivateHeaders"),
                .headerSearchPath("Hash/Keccak"),
                .headerSearchPath("Hash/Blake2b"),
                .headerSearchPath("Ed25519"),
                .headerSearchPath("EdDSA")
            ]
        ),
        .target(
            name: "WalletLibCrypto",
            dependencies: ["WalletLibCryptoC"],
            path: "WalletLibCrypto",
            exclude: [
                "HexConverter",
                "Scripts",
                "Encoding",
                "Hash",
                "OpenSSL",
                "Crypto/Key",
                "Crypto/Ed25519",
                "Crypto/EdDSA",
                "Crypto/Curve",
                "Crypto/ECDSA",
                "Crypto/Bignum",
                "PrivateHeaders"
            ]
        ),
        .testTarget(
            name: "WalletLibCryptoTests",
            dependencies: ["WalletLibCrypto"],
            path: "WalletLibCryptoTests"
        )
    ]
)

