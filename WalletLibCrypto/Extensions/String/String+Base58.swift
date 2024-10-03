//
//  String+Base58.swift
//  WalletLibCrypto
//
//

import Foundation
import WalletLibCrypto.Base58


public extension String {
    
    
    func base58(usingChecksum: Bool, type: Base58EncodingType = .btc) -> String {
        
        guard let data = self.data(using: .utf8) else { return "" }
        
        if usingChecksum {
            
            return Base58.encodeUsedChecksum(data, type: type)
            
        } else {
            
            return Base58.encode(data, type: type)
            
        }
    }
    
    
    func base58decode(usingChecksum: Bool, type: Base58EncodingType = .btc) -> Data {
        
        if usingChecksum {
            
            return Base58.decodeUsedChecksum(self, type: type)
            
        } else {
            
            return Base58.decode(self, type: type)
            
        }
    }
    
    
}
