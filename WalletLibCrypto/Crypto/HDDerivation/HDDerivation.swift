//
//  HDDerivation.swift
//  WalletLibCrypto
//
//

import Foundation
import WalletLibCrypto.KeySecp256k1
import WalletLibCrypto.Base58
import CommonCrypto

/// HDDerivation allows you to generate keys in accordance with the standard described in
/// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki

public final class HDDerivation {
    public typealias SLIP_0132_PREFIXES = (pub: [UInt8], prv: [UInt8])

    /// BIP32  hmac key
    static public let HMACKey = "Bitcoin seed"

    private let master: ExtendedKeySecp256k1

    public var derived: ExtendedKeySecp256k1
    public var base58encoding: Base58EncodingType = .btc

    /// Extended public key for last derived key
    public var extPub: String {
        derived.serializedPub(base58encoding)
    }

    /// Extended private key for last derived key
    public var extPrv: String {
        derived.serializedPrv(base58encoding)
    }

    // MARK: - Init

    /// Initialize with seed
    /// - Parameter seed: Seed data
    public init(seed: Data, slip0132 prefix: SLIP_0132_PREFIXES) {
        let pass = HDDerivation.HMACKey.data(using: .ascii) ?? Data() // "Bitcoin seed"
        var output = [UInt8](repeating: .zero, count: Int(CC_SHA512_DIGEST_LENGTH))

        seed.withUnsafeBytes { seedPtr in
            pass.withUnsafeBytes { passPtr in
                CCHmac(
                    CCHmacAlgorithm(kCCHmacAlgSHA512),
                    passPtr.baseAddress, pass.count,
                    seedPtr.baseAddress, seed.count,
                    &output
                )
            }
        }

        let outputData = Data(output)
        let key = KeySecp256k1(privateKey: outputData.prefix(32))
        let extendedKey = ExtendedKeySecp256k1(
            key: key,
            chaincode: outputData.suffix(32),
            prefixPub: Data(prefix.pub),
            prefixPrv: Data(prefix.prv)
        )

        master = extendedKey
        derived = ExtendedKeySecp256k1(extendedKey: extendedKey)
    }
    
    /// Initialize with serialized extended key string
    /// - Parameter base58string: Serialized extended key
    public init(base58string: String, type: KeyType, encodingType: Base58EncodingType = .btc) {
        master = ExtendedKeySecp256k1(serializedString: base58string, type: type, encodingType: encodingType)
        derived = ExtendedKeySecp256k1(serializedString: base58string, type: type, encodingType: encodingType)
        base58encoding = encodingType
    }
    
    /// Initialize with extended key
    /// - Parameter extendedKey: Extended key
    public init(extendedKey: ExtendedKeySecp256k1) {
        master = extendedKey
        derived = ExtendedKeySecp256k1(extendedKey: extendedKey)
    }

    // MARK: - Public methods

    /// Derive key for BIP32 deivation path
    /// - Parameter path: Derivation path string (e.g. 'm/44'/60'/0'/0')
    /// - Throws: HDDerivationError.wrongPath
    public func derive(for path: String) throws {
        let chunks = path.replacingOccurrences(of: "m/", with: "").components(separatedBy: CharacterSet.init(charactersIn: "/"))

        if chunks.count < 1 {
            throw HDDerivationError.wrongPath
        }
        
        for chunk in chunks {
            let isHardened = chunk.hasSuffix("'")
            guard let sequence: UInt32 = isHardened ? UInt32(chunk.replacingOccurrences(of: "'", with: "")) : UInt32(chunk) else {
                throw HDDerivationError.wrongPath
            }
            derive(sequence: sequence, hardened: isHardened)
        }
    }

    /// Derive a key at the specified sequence and 'hardened' flag
    /// - Parameter sequence: Sequence value
    /// - Parameter hardened: Flag indicates whether the child key is a strong key
    public func derive(sequence: UInt32, hardened: Bool) {
        derived.derived(sequence, hardened: hardened)
    }
    
    /// Resets  to  initial state. Used if need to change the BIP32 path.
    public func reset() {
        derived = ExtendedKeySecp256k1(extendedKey: master);
    }

    /// Derive a child key using the last derived key
    /// - Parameter sequence: Sequence value
    /// - Parameter hardened: Flag that indicates whether the child key is a strong key
    public func deriveChild(for sequence: UInt, hardened: Bool) -> ExtendedKeySecp256k1 {
        let key = ExtendedKeySecp256k1(extendedKey: derived)
        key.derived(UInt32(sequence), hardened: hardened)
        return key
    }
}
