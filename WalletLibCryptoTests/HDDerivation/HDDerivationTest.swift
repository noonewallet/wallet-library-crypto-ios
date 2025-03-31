//
//  HDDerivationTest.swift
//  WalletLibCryptoTests
//
//

import XCTest
@testable import WalletLibCrypto

final class HDDerivationTest: XCTestCase {
    private typealias SUT = HDDerivation

    private let DEFAULT_SLIP0132: ([UInt8], [UInt8]) = ([0x04, 0x88, 0xB2, 0x1E], [0x04, 0x88, 0xAD, 0xE4])

    func test_init_fromSeedProducesDeterministicMasterKey() {
        let mockSeedHex = "1ed7acf97f946c0311de6fd968e62f8b4d1ff17ff883f7672fd9cc9f7308157e4d4ff194cd9536889f37b04c6c9821epP86851b14685fdfa15502e7dd6cf2c"
        let seed = Data(hex: mockSeedHex)

        let expectedPrivKeyHex = "300b155f751964276c0536230bd9b16fe7a86533c3cbaa7575e8d0431dbedf23"
        let expectedChainCodeHex = "f9945bb8b052bd0b0802c10c7c852e7765b69b61ce7233d9fe5a35ab108ca3b6"

        let sut: SUT = SUT(seed: seed, slip0132: DEFAULT_SLIP0132)
        let privKeyData = sut.derived.key.data
        let chainCodeData = sut.derived.chaincode

        XCTAssertEqual(privKeyData.hex, expectedPrivKeyHex, "Private key doesn't match expected value")
        XCTAssertEqual(chainCodeData.hex, expectedChainCodeHex, "Chaincode doesn't match expected value")
    }

    func testVectors() {
        
        var seed = Data(hex: TestVectors.vector1.seed)
        var derivation = HDDerivation(seed: seed, slip0132: DEFAULT_SLIP0132)
        
        for element in TestVectors.vector1.1 {
            
            autoreleasepool(invoking: {
                
                try? derivation.derive(for: element.path)
                
                XCTAssertFalse(derivation.extPub != element.extpub, "Wrong extended public. Expected: \(element.extpub) Result: \(derivation.extPub)")
                XCTAssertFalse(derivation.extPrv != element.extprv, "Wrong extended private. Expected: \(element.extprv) Result: \(derivation.extPrv)")
                
                derivation.reset()
                
            })
            
        }
        
        seed = Data(hex: TestVectors.vector2.seed)
        derivation = HDDerivation(seed: seed, slip0132: DEFAULT_SLIP0132)

        for element in TestVectors.vector2.1 {
            
            autoreleasepool(invoking: {
                
                try? derivation.derive(for: element.path)
                
                XCTAssertFalse(derivation.extPub != element.extpub, "Wrong extended public. Expected: \(element.extpub) Result: \(derivation.extPub)")
                XCTAssertFalse(derivation.extPrv != element.extprv, "Wrong extended private. Expected: \(element.extprv) Result: \(derivation.extPrv)")
                
                derivation.reset()
                
            })
            
        }

        seed = Data(hex: TestVectors.vector3.seed)
        derivation = HDDerivation(seed: seed, slip0132: DEFAULT_SLIP0132)

        for element in TestVectors.vector3.1 {
            
            autoreleasepool(invoking: {
                
                try? derivation.derive(for: element.path)
                
                XCTAssertFalse(derivation.extPub != element.extpub, "Wrong extended public. Expected: \(element.extpub) Result: \(derivation.extPub)")
                XCTAssertFalse(derivation.extPrv != element.extprv, "Wrong extended private. Expected: \(element.extprv) Result: \(derivation.extPrv)")
                
                derivation.reset()
                
            })
            
        }
    }
    
    func testGenerationVectors() {
        
        var seed = Data(hex: TestPublicPrivateKeysVector1.seed)
        var generator = HDDerivation(seed: seed, slip0132: DEFAULT_SLIP0132)
        try? generator.derive(for: TestPublicPrivateKeysVector1.externalpath)
        
        for i in 0..<TestPublicPrivateKeysVector1.externalIndexes.count {
            
            autoreleasepool(invoking: {
                
                let generated = generator.deriveChild(for: UInt(i), hardened: false)
                
                XCTAssertFalse(generated.serializedPub() != TestPublicPrivateKeysVector1.externalIndexes[i].extpub, "Wrong extended public. Expected: \(TestPublicPrivateKeysVector1.externalIndexes[i].extpub) Result: \(generated.serializedPub())")
                XCTAssertFalse(generated.serializedPrv() != TestPublicPrivateKeysVector1.externalIndexes[i].extprv, "Wrong extended private. Expected: \(TestPublicPrivateKeysVector1.externalIndexes[i].extprv) Result: \(generated.serializedPrv())")
                
            })
            
        }
        
        generator.reset()
        
        try? generator.derive(for: TestPublicPrivateKeysVector1.internalpath)
        
        for i in 0..<TestPublicPrivateKeysVector1.internalIndexes.count {
            
            autoreleasepool(invoking: {
                
                let generated = generator.deriveChild(for: UInt(i), hardened: false)
                
                XCTAssertFalse(generated.serializedPub() != TestPublicPrivateKeysVector1.internalIndexes[i].extpub, "Wrong extended public. Expected: \(TestPublicPrivateKeysVector1.internalIndexes[i].extpub) Result: \(generated.serializedPub())")
                XCTAssertFalse(generated.serializedPrv() != TestPublicPrivateKeysVector1.internalIndexes[i].extprv, "Wrong extended private. Expected: \(TestPublicPrivateKeysVector1.internalIndexes[i].extprv) Result: \(generated.serializedPrv())")
                
            })
            
        }
        
        seed = Data(hex: TestPublicPrivateKeysVector2.seed)
        generator = HDDerivation(seed: seed, slip0132: DEFAULT_SLIP0132)
        try? generator.derive(for: TestPublicPrivateKeysVector2.externalpath)

        for i in 0..<TestPublicPrivateKeysVector2.externalIndexes.count {
            
            autoreleasepool(invoking: {
                
                let generated = generator.deriveChild(for: UInt(i), hardened: false)
                
                XCTAssertFalse(generated.serializedPub() != TestPublicPrivateKeysVector2.externalIndexes[i].extpub, "Wrong extended public. Expected: \(TestPublicPrivateKeysVector2.externalIndexes[i].extpub) Result: \(generated.serializedPub())")
                XCTAssertFalse(generated.serializedPrv() != TestPublicPrivateKeysVector2.externalIndexes[i].extprv, "Wrong extended private. Expected: \(TestPublicPrivateKeysVector2.externalIndexes[i].extprv) Result: \(generated.serializedPrv())")
                
            })
            
        }

        generator.reset()

        try? generator.derive(for: TestPublicPrivateKeysVector2.internalpath)

        for i in 0..<TestPublicPrivateKeysVector2.internalIndexes.count {
            
            autoreleasepool(invoking: {
                
                let generated = generator.deriveChild(for: UInt(i), hardened: false)
                
                XCTAssertFalse(generated.serializedPub() != TestPublicPrivateKeysVector2.internalIndexes[i].extpub, "Wrong extended public. Expected: \(TestPublicPrivateKeysVector2.internalIndexes[i].extpub) Result: \(generated.serializedPub())")
                XCTAssertFalse(generated.serializedPrv() != TestPublicPrivateKeysVector2.internalIndexes[i].extprv, "Wrong extended private. Expected: \(TestPublicPrivateKeysVector2.internalIndexes[i].extprv) Result: \(generated.serializedPrv())")
                
            })
            
        }
        
        seed = Data(hex: TestPublicPrivateKeysVector3.seed)
        generator = HDDerivation(seed: seed, slip0132: DEFAULT_SLIP0132)
        try? generator.derive(for: TestPublicPrivateKeysVector3.externalpath)

        for i in 0..<TestPublicPrivateKeysVector3.externalIndexes.count {
            
            autoreleasepool(invoking: {
                
                let generated = generator.deriveChild(for: UInt(i), hardened: false)
                
                XCTAssertFalse(generated.serializedPub() != TestPublicPrivateKeysVector3.externalIndexes[i].extpub, "Wrong extended public. Expected: \(TestPublicPrivateKeysVector3.externalIndexes[i].extpub) Result: \(generated.serializedPub())")
                XCTAssertFalse(generated.serializedPrv() != TestPublicPrivateKeysVector3.externalIndexes[i].extprv, "Wrong extended private. Expected: \(TestPublicPrivateKeysVector3.externalIndexes[i].extprv) Result: \(generated.serializedPrv())")
                
            })
        }

        generator.reset()

        try? generator.derive(for: TestPublicPrivateKeysVector3.internalpath)

        for i in 0..<TestPublicPrivateKeysVector3.internalIndexes.count {
            
            autoreleasepool(invoking: {
                
                let generated = generator.deriveChild(for: UInt(i), hardened: false)
                
                XCTAssertFalse(generated.serializedPub() != TestPublicPrivateKeysVector3.internalIndexes[i].extpub, "Wrong extended public. Expected: \(TestPublicPrivateKeysVector3.internalIndexes[i].extpub) Result: \(generated.serializedPub())")
                XCTAssertFalse(generated.serializedPrv() != TestPublicPrivateKeysVector3.internalIndexes[i].extprv, "Wrong extended private. Expected: \(TestPublicPrivateKeysVector3.internalIndexes[i].extprv) Result: \(generated.serializedPrv())")
                
            })
            
        }
    }
    
    
}
