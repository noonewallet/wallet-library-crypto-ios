[![License](https://img.shields.io/badge/license-MIT-black.svg?style=flat)](https://mit-license.org)
[![Platform](https://img.shields.io/badge/platform-ios-blue.svg?style=flat)](https://developer.apple.com/resources/)
[![Swift](https://img.shields.io/badge/swift-5.0-brightgreen.svg)](https://developer.apple.com/resources/)
[![Version](https://img.shields.io/badge/Version-1.0-orange.svg)]()

![Noone core](https://github.com/noonewallet/noone-android-core-crypto/assets/111989613/1f062349-24d4-4824-9c00-b8f2724eca51)

## WalletLibCrypto

The WalletLibCrypto library is an implementation of tools related to cryptography. Included:

 __Keys:__
 [Secp256k1](WalletLibCrypto/Crypto/Key/KeySecp256k1.m) | [Ed25519 (implementation related to Cardano)](WalletLibCrypto/Crypto/Key/KeyEd25519.m)

 __Signatures:__ 
 [ECDSA](WalletLibCrypto/Crypto/ECDSA/ECDSA.m) | [EdDSA (Donna)](WalletLibCrypto/PrivateHeaders/ed25519-donna.h)

 __Enconding:__ 
 [Base58](WalletLibCrypto/Encoding/Base58/Base58.m) | [Bech32](WalletLibCrypto/Encoding/Bech32/Bech32.m) 

 __Hash:__ 
 [Sha(256, 512)](WalletLibCrypto/OpenSSL/headers/openssl/sha.h) | [RipeMD160](WalletLibCrypto/OpenSSL/headers/openssl/ripemd.h) | [Keccak256](WalletLibCrypto/Hash/Keccak/keccak-tiny.c) | [Blake2b(224, 256)](WalletLibCrypto/Hash/Blake2b/blake2b.c)

## Requirements

* macOS 12.6
* XCode Version 14.2

## Installation

Using `CocoaPods`. 

Clone or download repo, add the following line to your `Podfile`

```ruby
# platform :ios, '10.0'

target 'YourTargetName' do
  use_frameworks!
  
  pod 'WalletLibCrypto', :path => 'path/to/WalletLibCrypto' 
end
```

## Usage

#### ECDSA signature
```swift
    let hash = Data(hex: "fe9fcf4bb778de52d36b684925e099a447628a13cd261ccac1486022fcb2b0be")

    let privateKey = Data(hex: "776c223f2851c0bd0507ebd4b0619a61ae5f13fdc49cf234bd6d4a1032f3fdb0")

    var id: Int = 0

    let signature = SignatureECDSA.sign(nonce: .RFC6979, output: .DER, data: hash, key: privateKey, recid: &id)

```

#### Encoding and decoding base58

```swift
    let message = Data(hex: "fe9fcf4bb778de52d36b684925e099a447628a13cd261ccac1486022fcb2b0be")
                
    let base58encoded = Base58.encode(message)

    let base58decoded = Base58.decode(base58encoded)
```

#### Deriving public and private keys

```swift
    private let DEFAULT_SLIP0132: ([UInt8], [UInt8]) = ([0x04, 0x88, 0xB2, 0x1E], [0x04, 0x88, 0xAD, 0xE4])

    let seed = Data(hex: "000102030405060708090a0b0c0d0e0f")

    let derivation = HDDerivation(seed: seed, slip0132: DEFAULT_SLIP0132)
```

## Created using
* [_OpenSSL 1.1.1j_](https://github.com/openssl/openssl)
* [_keccak-tiny_](https://github.com/coruus/keccak-tiny)
* [_blake2b_](https://github.com/mjosaarinen/blake2_mjosref)
* [_ed25519_](https://github.com/input-output-hk/cardano-crypto)

## OpenSSL

WalletLibCrypto contains OpenSSL static libraries. You can build them using a [script](WalletLibCrypto/Scripts/openssl_update.sh "script")

## License

MIT. See the [_LICENSE_](LICENSE) file for more info.
