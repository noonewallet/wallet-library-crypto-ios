//
//  Base58Test.swift
//  WalletLibCryptoTests
//
//

import XCTest
@testable import WalletLibCrypto.Base58

final class Base58Test: XCTestCase {
    
    func testBase58EncodeDecode() {
        
        for (index, element) in TestData.vector2.enumerated() {
            
            autoreleasepool(invoking: {
                
                let message = Data(hex: element.hash)
                
                let base58encoded = Base58.encode(message)
                
                XCTAssertFalse(base58encoded.isEmpty, "Empty");
                XCTAssertFalse(base58encoded != expectedBase58Strings[index], "Wrong base58. Result: \(base58encoded), Expected: \(expectedBase58Strings[index])")
                
                let base58decoded = Base58.decode(base58encoded)
                
                XCTAssertFalse(base58decoded.hex != element.hash, "Wrong base58. Result: \(base58decoded.hex), Expected: \(element.hash)")
                
            })
            
        }
        
    }
}



