//
//  Data+Type.swift
//  WalletLibCrypto
//
//

import Foundation


public extension Data {
    
    
    func to<T>(type: T.Type) -> T {
        
        var data = Data(count: MemoryLayout<T>.size)
        _ = data.withUnsafeMutableBytes({ self.copyBytes(to: $0) })
        
        return data.withUnsafeBytes({ $0.load(as: T.self) })
    }
    
    
}
