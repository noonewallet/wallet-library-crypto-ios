//
//  GoogleDriveEncryption.swift
//  WalletLibCrypto
//
//

import CommonCrypto
import WalletLibCrypto.PBKDF2SHA512

public enum GoogleDriveEncryption {
    public static func foo(
        password: Data,
        salt: Data,
        iterations: Int32,
        keyLength: Int32
    ) -> Data {
        if let key = PBKDF2SHA512.derive(
            withPassword: password,
            salt: salt,
            iterations: iterations,
            keyLength: keyLength
        ) {
            return key
        }
        assertionFailure("Key is unexpectedly nil")
        return Data()
    }
    
    public static func bar(
        password: Data,
        salt: Data,
        iterations: Int32,
        keyLength: Int
    ) -> Data {
        let int8password = password.withUnsafeBytes {
            [Int8]($0.bindMemory(to: Int8.self))
        }
        
        let uint8salt = salt.withUnsafeBytes {
            [UInt8]($0)
        }
        
        var uint8seed = Array<UInt8>(repeating: 0, count: keyLength)
        
        CCKeyDerivationPBKDF(
            CCPBKDFAlgorithm(kCCPBKDF2),
            int8password,
            password.count,
            uint8salt,
            salt.count,
            CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA512),
            2048,
            &uint8seed,
            keyLength
        )
        
        let seed = Data(uint8seed)
        
        return seed
    }
}
