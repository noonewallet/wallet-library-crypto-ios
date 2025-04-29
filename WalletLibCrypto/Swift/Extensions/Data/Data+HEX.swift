//
//  Data+HEX.swift
//  WalletLibCrypto
//
//

import Foundation


public extension Data {
    
    
    init(hex: String) {
        
        let hexstr = hex.dropPrefix(prefix: "0x")
        var data = Data(capacity: (hex.count / 2) + (hex.count % 2))
        
        for hexByte in hexstr.components(maxLength: 2, backwards: true) {
            
            guard var byte = UInt8(hexByte, radix: 16) else {
                
                self = Data()
                
                return
                
            }
            
            data.append(&byte, count: 1)
            
        }

        self = data
    }
    
    
    var hex: String {
        
        return self.map({ String(format: "%02x", $0) }).joined()
    }
    
    
    var dropedPrefixZeros: Data {
        
        var lastValuePosition = 0
        
        for i in 0..<self.count {
            
            if self[i] != 0 { break }
            
            lastValuePosition += 1
            
        }
        
        return self.subdata(in: lastValuePosition..<count)
    }
    
    
}
