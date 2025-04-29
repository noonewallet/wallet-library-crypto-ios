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
            exclude: ["Scripts", "OpenSSL"],
            sources: [
                "Extensions",
                "Crypto/PBKDF2SHA512",
                "Crypto/Signature",
                "Crypto/HDDerivation"
            ]
        ),
        .testTarget(
            name: "WalletLibCryptoTests",
            dependencies: ["WalletLibCrypto"],
            path: "WalletLibCryptoTests"
        )
    ]
)

