//
//  KeyType.h
//  WalletLibCrypto
//
//

#ifndef KeyType_h
#define KeyType_h


typedef NS_ENUM(NSUInteger, KeyCompression) {
    
    CompressedConversion = 1,
    
    UncompressedConversion = 2
    
};


typedef NS_ENUM(NSUInteger, KeyType) {
    
    Public = 1,
    
    Private = 2
    
};


#endif /* KeyType_h */
