//
//  String+Hash.swift
//  WalletLibCrypto
//
//

import Foundation
import WalletLibCrypto.Hash


public extension String {
    
    
    func keccak() -> Data {
        
        guard let data = self.data(using: .utf8) else { return Data() }
        
        return Hash.keccak256(from: data)
    }
    
    
    func sha256() -> Data {
        
        guard let data = self.data(using: .utf8) else { return Data() }
        
        return Hash.sha256(from: data)
    }
    
    
    func sha256sha256() -> Data {
        
        guard let data = self.data(using: .utf8) else { return Data() }
        
        return Hash.sha256Double(from: data)
    }
    
    
    func sha512() -> Data {
        
        guard let data = self.data(using: .utf8) else { return Data() }
        
        return Hash.sha512(from: data)
    }
    
    
    func blake2b256() -> Data {
        
        guard let data = self.data(using: .utf8) else { return Data() }
        
        return Hash.blake2b256(from: data)
    }
    
    func blake2b512() -> Data {
        
        guard let data = self.data(using: .utf8) else { return Data() }
        
        return Hash.blake2b512(from: data)
    }
    
    
    func blake2b224() -> Data {
        
        guard let data = self.data(using: .utf8) else { return Data() }
        
        return Hash.blake2b224(from: data)
    }
    
    
    func ripemd160() -> Data {
        
        guard let data = self.data(using: .utf8) else { return Data() }
        
        return Hash.ripemd160(from: data)
    }
    
    
    func ripemd160sha256() -> Data {
        
        guard let data = self.data(using: .utf8) else { return Data() }
        
        return Hash.ripemd160Sha256(from: data)
    }
}
