//
//  Data+Hash.swift
//  WalletLibCrypto
//
//

import Foundation
import WalletLibCrypto.Hash


public extension Data {
    
    
    func keccak() -> Data {
        
        return Hash.keccak256(from: self)
    }
    
    
    func sha256() -> Data {
        
        return Hash.sha256(from: self)
    }
    
    
    func sha256sha256() -> Data {
        
        return Hash.sha256Double(from: self)
    }
    
    func sha512() -> Data {
        
        return Hash.sha512(from: self)
    }
    
    
    func blake2b256() -> Data {
        
        return Hash.blake2b256(from: self)
    }
    
    
    func blake2b224() -> Data {
        
        return Hash.blake2b224(from: self)
    }
    
    
    func ripemd160() -> Data {
        
        return Hash.ripemd160(from: self)
    }
    
    
    func ripemd160sha256() -> Data {
        
        return Hash.ripemd160Sha256(from: self)
    }
    
    
}
