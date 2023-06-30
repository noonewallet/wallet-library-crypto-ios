//
//  String+Base58.swift
//  WalletLibCrypto
//
//

import Foundation
import WalletLibCrypto.Base58


public extension String {
    
    
    func base58(usingChecksum: Bool) -> String {
        
        guard let data = self.data(using: .utf8) else { return "" }
        
        if usingChecksum {
            
            return Base58.encodeUsedChecksum(data)
            
        } else {
            
            return Base58.encode(data)
            
        }
    }
    
    
    func base58decode(usingChecksum: Bool) -> Data {
        
        if usingChecksum {
            
            return Base58.decodeUsedChecksum(self)
            
        } else {
            
            return Base58.decode(self)
            
        }
    }
    
    
}
