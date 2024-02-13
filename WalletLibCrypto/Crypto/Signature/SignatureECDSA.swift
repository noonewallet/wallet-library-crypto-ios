//
//  SignatureECDSA.swift
//  WalletLibCrypto
//
//

import Foundation
import WalletLibCrypto.ECDSA


public struct SignatureECDSA {

    
    /// ECDSA signing
    /// - Parameter nonce: Determines what nonce function and signature serialize type will be used
    /// - Parameter output: Determines what output type will be used
    /// - Parameter data: Input message (32 bytes long hash expected)
    /// - Parameter key: Private key data
    /// - Parameter recid: Inout variable for storing recovery identifier
    public static func sign(nonce fn: NonceFunction, output: SignOutputType, data: Data, key: Data, recid: inout Int) -> Data {
        
        ECDSA.sign(data, key: key, noncetype: fn, recid: &recid, outtype: output)
    }
    
    
    /// Validate ECDSA signature
    /// - Parameter signature: Signature data
    /// - Parameter data: Message that was signed
    /// - Parameter key: Private key used for signing
    /// - Parameter type: Serialize signature type  (DER/Compact)
    public static func validate(signature: Data, data: Data, for key: Data, type: SignOutputType) -> Bool {
        switch type {
        case .Compact:
            
            let publicKey = KeySecp256k1(privateKey: key).publicKeyCompressed(.CompressedConversion)
            
            return ECDSA.validateCompactSignature(signature, hash: data, forPublicKey: publicKey)
            
        case .DER:
            
            return ECDSA.validateSignature(signature, hash: data, forKey: key)
            
        @unknown default:
            
            return false
        }
    }
    
    
    /// Recovery public key data from a signature
    /// - Parameter signature: Signature data
    /// - Parameter hash: Message that was signed
    /// - Parameter compression: Public key point conversion type Compressed/Uncompressed
    public static func recoveryPublicKey(from signature: Data, hash: Data, compression: PublickKeyCompressionType) -> Data? {
        
        ECDSA.recoveryPublicKeySignature(signature, hash: hash, compression: compression)
    }
}
