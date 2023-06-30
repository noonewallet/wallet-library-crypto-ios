//
//  Data+Base58.swift
//  WalletLibCrypto
//
//

import Foundation


public extension Data {
    
    
    func base58(usingChecksum: Bool) -> String {
        
        if usingChecksum {
            
            return Base58.encodeUsedChecksum(self)
            
        } else {
            
            return Base58.encode(self)
            
        }
    }
    
    
    func base58decode(usingChecksum: Bool) -> Data {
        
        guard let str = String(data: self, encoding: .utf8) else { return Data() }
        
        if usingChecksum {
            
            return Base58.decodeUsedChecksum(str)
            
        } else {
            
            return Base58.decode(str)
            
        }
    }
    
    
}
