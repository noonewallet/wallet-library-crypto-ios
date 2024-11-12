//
//  PBKDF2SHA512.swift
//  WalletLibCrypto
//
//

import CommonCrypto

public enum PBKDF2SHA512 {
    private static let iterations: UInt32 = 2048
    private static let keyLength = 32
    
    public static func makeAESKey(password: Data, salt: Data) -> Data? {
        var derivedKey = Data(count: keyLength)
        
        let result = derivedKey.withUnsafeMutableBytes { derivedKeyBytes in
            password.withUnsafeBytes { passwordBytes in
                salt.withUnsafeBytes { saltBytes in
                    CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        passwordBytes.baseAddress,
                        password.count,
                        saltBytes.baseAddress,
                        salt.count,
                        CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA512),
                        iterations,
                        derivedKeyBytes.baseAddress,
                        keyLength
                    )
                }
            }
        }
        
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
    
    public static func decryptEntropy(encryptedData: Data, aesKey: Data) -> Data? {
        let iv = encryptedData.prefix(kCCBlockSizeAES128)
        let cipherText = encryptedData.dropFirst(kCCBlockSizeAES128)

        guard aesKey.count == kCCKeySizeAES256, iv.count == kCCBlockSizeAES128 else {
            assertionFailure("Invalid key or IV length.")
            return nil
        }

        let bufferSize = cipherText.count + kCCBlockSizeAES128
        var buffer = Data(count: bufferSize)
        var dataOutMoved: size_t = 0

        let status = aesKey.withUnsafeBytes { keyBytes in
            iv.withUnsafeBytes { ivBytes in
                cipherText.withUnsafeBytes { cipherBytes in
                    buffer.withUnsafeMutableBytes { bufferBytes in
                        CCCrypt(
                            CCOperation(kCCDecrypt),
                            CCAlgorithm(kCCAlgorithmAES),
                            CCOptions(kCCOptionPKCS7Padding),
                            keyBytes.baseAddress,
                            aesKey.count,
                            ivBytes.baseAddress,
                            cipherBytes.baseAddress,
                            cipherText.count,
                            bufferBytes.baseAddress,
                            bufferSize,
                            &dataOutMoved
                        )
                    }
                }
            }
        }

        guard status == kCCSuccess else {
            assertionFailure("Decryption failed with status: \(status)")
            return nil
        }

        buffer.count = dataOutMoved
        return buffer
    }
    
    public static func makeEhash(encryptedData: Data) -> Data? {
        encryptedData.blake2b128()
    }
    
    public static func makeEid(encryptedData: Data, password: Data) -> Data? {
        (encryptedData + password).blake2b256()
    }
}
