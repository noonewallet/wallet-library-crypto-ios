//
//  ECDSATest.swift
//  WalletLibCryptoTests
//
//

import XCTest
@testable import WalletLibCrypto

final class ECDSATest: XCTestCase {
    
    func testSignature() {
        for testData in TestData.vector1 {
            autoreleasepool(invoking: {
                let hash = Data(hex: testData.hash)
                let privateKey = Data(hex: testData.key)
                var id: Int = 0

                let signature = SignatureECDSA.sign(nonce: .RFC6979, output: .DER, data: hash, key: privateKey, recid: &id)
                
                let expectedSignature = Data(hex: testData.expectedSign)

                XCTAssertFalse(signature != expectedSignature, "Wrong signature")
                XCTAssertFalse(id != testData.expectedRecId, "Wrong rec id")
                XCTAssertFalse(!SignatureECDSA.validate(signature: signature, data: hash, for: privateKey, type: .DER), "Validation failure")
            })
        }
        
        for testData in TestData.vector2 {
            autoreleasepool(invoking: {
                let hash = Data(hex: testData.hash)
                let privateKey = Data(hex: testData.key)
                var id: Int = 0

                let signature = SignatureECDSA.sign(nonce: .RFC6979, output: .Compact, data: hash, key: privateKey, recid: &id).dropLast()
                let expectedSignature = Data(hex: testData.expectedSign)

                XCTAssertFalse(signature != expectedSignature, "Wrong signature \n\(signature.hex)\n\(expectedSignature.hex)")
                XCTAssertFalse(id != testData.expectedRecId, "Wrong rec id")
                XCTAssertFalse(!SignatureECDSA.validate(signature: signature, data: hash, for: KeySecp256k1(privateKey: privateKey).publicKeyCompressed(.CompressedConversion), type: .Compact), "Validation failure")

                if let pubkey = SignatureECDSA.recoveryPublicKey(from: signature, hash: hash, compression: .Compressed) {
                    XCTAssertFalse(pubkey.hex != testData.recoveredPublickKey, "Wrong recovered public key")
                } else {
                    XCTAssertFalse(false, "Can't recovery publik key")
                }
            })
        }

        for testData in TestData.eosSampleData {
            autoreleasepool(invoking: {
                let hash = Data(hex: testData.hash)
                let privateKey = Data(hex: testData.key)
                var id: Int = 0

                let signature = SignatureECDSA.sign(nonce: .EOS, output: .Compact, data: hash, key: privateKey, recid: &id).dropLast()
                let expectedSignature = Data(hex: testData.expectedSign)

                id = id + 4 + 27
                XCTAssertFalse(signature != expectedSignature,
                               "Wrong signature \n\(signature.hex)\n\(expectedSignature.hex) \n message \(testData.hash) key \(testData.key)")
                
                XCTAssertFalse(id != testData.expectedRecId, "Wrong rec id")
                XCTAssertFalse(!SignatureECDSA.validate(signature: signature, data: hash, for: KeySecp256k1(privateKey: privateKey).publicKeyCompressed(.CompressedConversion), type: .Compact), "Validation failure")

                if let pubkey = SignatureECDSA.recoveryPublicKey(from: signature, hash: hash, compression: .Compressed) {
                    XCTAssertFalse(pubkey.hex != testData.recoveredPublickKey, "Wrong recovered public key")
                } else {
                    XCTAssertFalse(false, "Can't recovery publik key")
                }
            })
        }
    
    }
    
    func testSign() {
        let key = "90add963eca315deec1e8373a965e18290663f569a75b20efb2c99771d055b75"
        let keyData = Data(hex: key)
        
        let message = "69da3e6e17b1bb9d82921e58230e3cb00e9e8f00d04b3c8843e1869d9fbe6659"
        let hash = Data(hex: message)

        var id: Int = 0
        let signature = SignatureECDSA.sign(nonce: .RFC6979, output: .Compact, data: hash, key: keyData, recid: &id).dropLast()
        
        let recid = UInt8(id + 27 + 2 + 8)
        
        if let pubkey = SignatureECDSA.recoveryPublicKey(from: Data(signature) + Data([recid]), hash: hash, compression: .Uncompressed) {
            XCTAssertTrue(pubkey == KeySecp256k1(privateKey: keyData).publicKeyCompressed(.UncompressedConversion), "Wrong recovered public key. Expected: \(KeySecp256k1(privateKey: keyData).publicKeyCompressed(.UncompressedConversion).hex) Result: \(pubkey.hex)")
        } else {
            XCTAssertFalse(false, "Can't recovery public key")
        }
    }

}
