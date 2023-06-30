//
//  KeySecp256k1Test.swift
//  WalletLibCryptoTests
//
//

import XCTest
import WalletLibCrypto.KeySecp256k1


final class KeySecp256k1Test: XCTestCase {
    
    
    func testKey() {
        
        for (index, element) in TestData.vector1.enumerated() {
            
            autoreleasepool(invoking: {
                
                let privated = Data(hex: element.key)
                let publicd = Data(hex: TestData.vectorRecoveredPublicKeys[index])
                
                let key = KeySecp256k1(privateKey: privated)
                let publick = key.publicKeyCompressed(.CompressedConversion)
                
                XCTAssertTrue(publicd.hex == publick.hex, "Wrong key \(publick.hex) expected \(publicd.hex)")
                
            })
            
        }
        
    }
    
    
    func testExtendedKeys() {
        
        for element in TestVectors.vector1.1 {
            
            autoreleasepool(invoking: {
                
                let extendPublic = ExtendedKeySecp256k1(serializedString: element.extpub, type: .Public)
                let extendPrivate = ExtendedKeySecp256k1(serializedString: element.extprv, type: .Private)
                
                XCTAssertFalse(extendPublic.key.type != .Public, "Wrong type \(extendPublic.serializedPub())")
                XCTAssertFalse(extendPrivate.key.type != .Private, "Wrong type \(extendPrivate.serializedPrv())")
                
                XCTAssertFalse(extendPublic.serializedPub() != element.extpub, "Extended key error expected \(element.extpub) result \(extendPublic.serializedPub())")
                XCTAssertFalse(extendPrivate.serializedPrv() != element.extprv, "Extended key error expected \(element.extprv) result \(extendPrivate.serializedPrv())")
                
            })
            
        }
        
        for element in TestVectors.vector2.1 {
            
            autoreleasepool(invoking: {
                
                let extendPublic = ExtendedKeySecp256k1(serializedString: element.extpub, type: .Public)
                let extendPrivate = ExtendedKeySecp256k1(serializedString: element.extprv, type: .Private)
                
                XCTAssertFalse(extendPublic.key.type != .Public, "Wrong type \(extendPublic.serializedPub())")
                XCTAssertFalse(extendPrivate.key.type != .Private, "Wrong type \(extendPrivate.serializedPrv())")
                
                XCTAssertFalse(extendPublic.serializedString() != element.extpub, "Extended key error expected \(element.extpub) result \(extendPublic.serializedPub())")
                XCTAssertFalse(extendPrivate.serializedPrv() != element.extprv, "Extended key error expected \(element.extprv) result \(extendPrivate.serializedPrv())")
                
            })
            
        }
        
        for element in TestVectors.vector3.1 {
            
            autoreleasepool(invoking: {
                
                let extendPublic = ExtendedKeySecp256k1(serializedString: element.extpub, type: .Public)
                let extendPrivate = ExtendedKeySecp256k1(serializedString: element.extprv, type: .Private)
                
                XCTAssertFalse(extendPublic.key.type != .Public, "Wrong type \(extendPublic.serializedPub())")
                XCTAssertFalse(extendPrivate.key.type != .Private, "Wrong type \(extendPrivate.serializedPrv())")
                
                XCTAssertFalse(extendPublic.serializedPub() != element.extpub, "Extended key error expected \(element.extpub) result \(extendPublic.serializedPub())")
                XCTAssertFalse(extendPrivate.serializedPrv() != element.extprv, "Extended key error expected \(element.extprv) result \(extendPrivate.serializedPrv())")
                
            })
            
        }
        
    }
    
}

