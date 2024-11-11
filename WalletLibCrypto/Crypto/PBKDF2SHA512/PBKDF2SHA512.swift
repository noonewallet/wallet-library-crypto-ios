//
//  PBKDF2SHA512.swift
//  WalletLibCrypto
//
//

import CommonCrypto

public enum PBKDF2SHA512 {
    public static func makeAESKey(
        password: Data,
        salt: Data,
        iterations: UInt32,
        keyLength: Int
    ) -> Data? {
        // Prepare output buffer for the derived key
        var derivedKey = Data(count: keyLength)
        
        // Use `withUnsafeBytes` to access the data in a safe way
        let result = derivedKey.withUnsafeMutableBytes { derivedKeyBytes in
            password.withUnsafeBytes { passwordBytes in
                salt.withUnsafeBytes { saltBytes in
                    // Call CCKeyDerivationPBKDF with Swift's safe pointers
                    CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        passwordBytes.baseAddress,
                        password.count,
                        saltBytes.baseAddress,
                        salt.count,
                        CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA512),
                        iterations,
                        derivedKeyBytes.bindMemory(to: UInt8.self).baseAddress,
                        keyLength
                    )
                }
            }
        }
        
        // Check if the operation was successful
        guard result == kCCSuccess else {
            assertionFailure("Key derivation failed with status: \(result)")
            return nil
        }
        
        return derivedKey
    }
    
    public static func encryptEntropy(entropy: Data, aesKey: Data, iv: Data) -> Data? {
        guard aesKey.count == kCCKeySizeAES256, iv.count == kCCBlockSizeAES128 else {
            assertionFailure("Invalid key or IV length.")
            return nil
        }
        
        let bufferSize = entropy.count + kCCBlockSizeAES128
        var buffer = Data(count: bufferSize)
        var dataOutMoved: size_t = 0
        
        let status = aesKey.withUnsafeBytes { keyBytes in
            iv.withUnsafeBytes { ivBytes in
                entropy.withUnsafeBytes { entropyBytes in
                    buffer.withUnsafeMutableBytes { bufferBytes in
                        CCCrypt(
                            CCOperation(kCCEncrypt),
                            CCAlgorithm(kCCAlgorithmAES),
                            CCOptions(kCCOptionPKCS7Padding),
                            keyBytes.baseAddress,
                            aesKey.count,
                            ivBytes.baseAddress,
                            entropyBytes.baseAddress,
                            entropy.count,
                            bufferBytes.baseAddress,
                            bufferSize,
                            &dataOutMoved
                        )
                    }
                }
            }
        }
        
        guard status == kCCSuccess else {
            assertionFailure("Encryption failed with status: \(status)")
            return nil
        }
        
        buffer.count = dataOutMoved
        return iv + buffer
    }
}
