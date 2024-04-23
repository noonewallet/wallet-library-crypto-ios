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
    
    func testBase58RippleEncodeSuccess() {
        
        for (hex, data) in base58RippleValidTestData {
            
            autoreleasepool(invoking: {
                
                let message = Data(hex: hex)
                
                let base58encoded = Base58.encode(message, type: .ripple)
                
                XCTAssertFalse(base58encoded != data, "Base58 encoding error. Result: \(base58encoded), Expected: \(data)")
                
            })
            
        }
        
    }
    
    func testBase58RippleDecodeSuccess() {
        
        for (hex, data) in base58RippleValidTestData {
            
            autoreleasepool(invoking: {
                
                let base58decoded = Base58.decode(data, type: .ripple)

                XCTAssertFalse(base58decoded.hex != hex, "Base58 decoding error. Result: \(base58decoded.hex), Expected: \(hex)")
                
            })
            
        }
        
    }
    
    func testBase58RippleDecodeFailure() {
        
        for data in base58RippleInvalidTestData {
            
            autoreleasepool(invoking: {
                
                let base58decoded = Base58.decode(data, type: .ripple)

                XCTAssertFalse(!base58decoded.isEmpty, "Base58 decoding error. Result: \(base58decoded.hex), Expected: empty")
                
            })
            
        }
        
    }
}



