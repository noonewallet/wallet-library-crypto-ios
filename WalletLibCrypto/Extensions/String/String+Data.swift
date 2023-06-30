//
//  String+DataConvertible.swift
//  WalletLibCrypto
//
//

import Foundation


extension String: DataConvertibleProtocol {
    
    public var data: Data {
        
        guard let result = data(using: .ascii) else { return Data() }
        
        return result
    }
    
}
