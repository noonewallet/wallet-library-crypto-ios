//
//  PBKDF2SHA512Tests.swift
//  WalletLibCryptoTests
//
//

import XCTest
@testable import WalletLibCrypto

final class PBKDF2SHA512Tests: XCTestCase {

    func testKey() async throws {
        let expectedEid = Data(hex: "39f2d14470847bdbf54f8e7f34dbfc05233b5873f85cd0afa38214063b0bc219")
        let expectedEHash = Data(hex: "22fd77f2810af3bac955df8c97df233b")
        let expectedEncryptedData = Data(hex: "362344ae7dddc409d8f9f7bfd166167146426d95486bd4d8efecff96b3293efb4b740247ab74a93d2e1cc13a6312b118")
        let expectedKeyBytes = Data(hex: "9cc05ea53ae91b04c76adf0ead2a7ec9a71e4e3a09598b9c95891e6c2fac6970")

        // apart trigger volcano change focus off yard copper heavy work annual into security blade subject
        let entropy = Data(hex: "0a5d13d69315a332bfb17f6a7fb025baec2c2e35")
        let iv = Data(hex: "362344ae7dddc409d8f9f7bfd1661671")
        let password = "1234".data(using: .utf8)!
        let salt = "69c41473e1fadc65b310546a03bbb0e697b5e1d0d2138eff08455dec855afc7f".data(using: .utf8)!
        
        let aesKey = PBKDF2SHA512.makeAESKey(password: password, salt: salt)!
        
        let encryptedData = PBKDF2SHA512.encryptEntropy(
            entropy: entropy,
            aesKey: aesKey,
            iv: iv
        )!
        
        let ehash = PBKDF2SHA512.makeEhash(encryptedData: encryptedData)!
        let eid = PBKDF2SHA512.makeEid(encryptedData: encryptedData, password: password)!
        
        XCTAssertEqual(expectedKeyBytes.hex, aesKey.hex)
        XCTAssertEqual(expectedEncryptedData.hex, encryptedData.hex)
        XCTAssertEqual(expectedEHash.hex, ehash.hex)
        XCTAssertEqual(expectedEid.hex, eid.hex)
    }
}
