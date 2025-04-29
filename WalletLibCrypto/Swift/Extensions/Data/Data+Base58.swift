//
//  Data+Base58.swift
//  WalletLibCrypto
//
//

import Foundation


public extension Data {
    
    
    func base58(usingChecksum: Bool, type: Base58EncodingType = .btc) -> String {
        
        if usingChecksum {
            
            return Base58.encodeUsedChecksum(self, type: type)
            
        } else {
            
            return Base58.encode(self, type: type)
            
        }
    }
    
    
    func base58decode(usingChecksum: Bool, type: Base58EncodingType = .btc) -> Data {
        
        guard let str = String(data: self, encoding: .utf8) else { return Data() }
        
        if usingChecksum {
            
            return Base58.decodeUsedChecksum(str, type: type)
            
        } else {
            
            return Base58.decode(str, type: type)
            
        }
    }
    
    
}
