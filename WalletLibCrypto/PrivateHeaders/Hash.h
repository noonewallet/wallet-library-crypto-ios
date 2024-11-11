//
//  Hash.h
//  WalletLibCrypto
//
//

#ifndef Hash_h
#define Hash_h


#import <Foundation/Foundation.h>


NS_ASSUME_NONNULL_BEGIN


@interface Hash : NSObject


+ (nonnull NSData *)keccak256From:(nonnull NSData *)data;


+ (nonnull NSData *)sha256From:(nonnull NSData *)data;


+ (nonnull NSData *)sha512From:(nonnull NSData *)data;


+ (nonnull NSData *)sha256DoubleFrom:(nonnull NSData *)data;


+ (nonnull NSData *)blake2b128From:(nonnull NSData *)data;


+ (nonnull NSData *)blake2b256From:(nonnull NSData *)data;


+ (nonnull NSData *)blake2b512From:(nonnull NSData *)data;


+ (nonnull NSData *)blake2b224From:(nonnull NSData *)data;


+ (nonnull NSData *)ripemd160From:(nonnull NSData *)data;


+ (nonnull NSData *)ripemd160Sha256From:(nonnull NSData *)data;


@end


NS_ASSUME_NONNULL_END


#endif /* Hash_h */
