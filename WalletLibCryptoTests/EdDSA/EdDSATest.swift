//
//  EdDSA.swift
//  WalletLibCryptoTests
//
//

import XCTest
@testable import WalletLibCrypto
@testable import WalletLibCrypto.KeyTweetNacl

final class EdDSATest: XCTestCase {

    func testTweetNaclSign() {
        let key = "34aebb9ea454967f16c407c0f8877763e86212116468169d93a3dcbcafe530c95754865e86d0ade1199301bbb0319a25ed6b129c4b0a57f28f62449b3df9c522"
        let keyData = Data(hex: key)
        
        let pubkey = KeyTweetNacl(privateKey: keyData).publicKey()
        
        
        let message = "d5cdb23936789f2cd09bbc8abe707fc5d45457932ab2a58345751e576977e6ad"
        let hash = Data(hex: message)

        let signature = SignatureEdDSA.signtwncl(data: hash, key: keyData)
        
        XCTAssertEqual(signature.hex, "44811dcddfd331b4cf82f2ae62532e0edca1976bdf50b48e6ec3e108347cbb47dddfccb4a8980f3aed4417084b62268f8f19cccd3940835de54c515172295703d5cdb23936789f2cd09bbc8abe707fc5d45457932ab2a58345751e576977e6ad", "Signatures are not equal")
        
        XCTAssertTrue(SignatureEdDSA.validatetwncl(signature: signature, data: hash, for: pubkey), "Signature is wrong")
        
    }

}
