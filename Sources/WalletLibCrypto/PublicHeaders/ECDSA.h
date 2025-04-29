//
//  ECDSA.h
//  WalletLibCrypto
//
//

#ifndef ECDSA_h
#define ECDSA_h


@interface ECDSA : NSObject


typedef NS_ENUM(NSUInteger, SignOutputType) {
    Compact = 1,
    DER = 2
};


typedef NS_ENUM(NSUInteger, NonceFunction) {
    RFC6979 = 1,
    EOS = 2
};


typedef NS_ENUM(NSUInteger, PublickKeyCompressionType) {
    Compressed = 1,
    Uncompressed = 2
};


NS_ASSUME_NONNULL_BEGIN


+ (nonnull NSData *)sign:(nonnull NSData *)hash key:(nonnull NSData *)key noncetype:(NonceFunction)noncetype recid:(nullable NSInteger *)recid outtype:(SignOutputType)outputType;


+ (BOOL)validateSignature:(nonnull NSData *)signature hash:(nonnull NSData *)hash forKey:(nonnull NSData *)key;


+ (BOOL)validateCompactSignature:(nonnull NSData *)compactSignature hash:(nonnull NSData *)hash forPublicKey:(nonnull NSData *)key;


+ (nullable NSData *)recoveryPublicKeySignature:(nonnull NSData *)compactSignature hash:(nonnull NSData *)hash compression:(enum PublickKeyCompressionType)compression;


NS_ASSUME_NONNULL_END


@end


#endif /* ECDSA_h */
