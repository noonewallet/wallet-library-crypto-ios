//
//  HDDerivationEd25519.swift
//  WalletLibCrypto
//
//

import Foundation
import WalletLibCrypto.KeyEd25519
import CommonCrypto


public class HDDerivationEd25519 {
    
    
    private let master: ExtendedKeyEd25519
    
    
    public var derived: ExtendedKeyEd25519
    
    
    public init(entropy: Data, password: String = "") {

        let outputLength = 96
        var output = Array<UInt8>(repeating: 0, count: outputLength)
        
        let passphrase = password.decomposedStringWithCompatibilityMapping.data(using: .utf8)
        
        let uint8passphrase = passphrase!.withUnsafeBytes({
            [Int8]($0.bindMemory(to: Int8.self))
        })
        
        let uint8salt = [UInt8](entropy)
        
        CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2), uint8passphrase, uint8passphrase.count, uint8salt, uint8salt.count, CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA512), 4096, &output, outputLength)
        
        var prvKey = Data(output[0..<64])
        let cc = Data(output[64..<output.count])
        
        prvKey[0]  &= 248;   /* clears the bottom 3 bits */
        prvKey[31] &= 0x1F;  /* clears the 3 highest bits */
        prvKey[31] |= 64;    /* set the 2nd highest bit */
        
        let key = KeyEd25519(privateKey: prvKey)
        
        let derivationKey = ExtendedKeyEd25519(key: key, chaincode: cc)

        master = derivationKey
        derived = ExtendedKeyEd25519(key: key, chaincode: cc)
    }
    
    
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
        
        derived.derive(sequence, hardened: hardened)
    }
    
    
    /// Resets to initial state. Used if need to change the BIP32 path.
    public func reset() {
        
        derived = ExtendedKeyEd25519(extendedKeyEd25519: master);
    }
    
    
    /// Derive a child key using the last derived key
    /// - Parameter sequence: Sequence value
    /// - Parameter hardened: Flag that indicates whether the child key is a strong key
    public func deriveChild(for sequence: UInt, hardened: Bool) -> ExtendedKeyEd25519 {
        
        let key = ExtendedKeyEd25519(extendedKeyEd25519: derived)
        key.derive(UInt32(sequence), hardened: hardened)
        
        return key
    }
}
