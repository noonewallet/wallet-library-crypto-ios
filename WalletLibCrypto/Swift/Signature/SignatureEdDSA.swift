//
//  SignatureEdDSA.swift
//  WalletLibCrypto
//
//

import Foundation
import WalletLibCrypto.EdDSA


public struct SignatureEdDSA {
    
    /// Signature using EdDSA Donna
    /// - Parameters:
    ///   - data: Input message (32 bytes long hash expected)
    ///   - key: Private key data
    public static func sign(data: Data, key: Data) -> Data {
        return EdDSA.sign(data, donnaKey: key)
    }
    
    /// Validate EdDSA Donna signature
    /// - Parameters:
    ///   - signature: Signature data
    ///   - data: Message that was signed
    ///   - key: Verification key (public key)
    public static func validate(signature: Data, data: Data, for key: Data) -> Bool {
        return EdDSA.validateDonnaSignature(signature, message: data, forPublicKey: key)
    }
    
    /// Signature using EdDSA TweetNacl
    /// - Parameters:
    ///   - data: Input message (32 bytes long hash expected)
    ///   - key: Private key data
    public static func signtwncl(data: Data, key: Data) -> Data {
        return EdDSA.sign(data, tweetnacl: key)
    }
    
    /// Validate EdDSA TweetNacl signature
    /// - Parameters:
    ///   - signature: Signature data
    ///   - data: Message that was signed
    ///   - key: Verification key (public key)
    public static func validatetwncl(signature: Data, data: Data, for key: Data) -> Bool {
        return EdDSA.validateTweetNaclSignature(signature, message: data, forPublicKey: key)
    }
    
}
