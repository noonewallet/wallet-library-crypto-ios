//
//  KeySecp256k1.h
//  WalletLibCrypto
//
//

#ifndef KeySecp256k1_h
#define KeySecp256k1_h


#import <Foundation/Foundation.h>
#import "KeyType.h"


NS_ASSUME_NONNULL_BEGIN


@interface KeySecp256k1 : NSObject <NSCopying>


@property (nonatomic, readonly, assign) KeyType type;


@property (nonatomic, readonly, nonnull) NSData *data;

- (instancetype)initWithPublicKey:(NSData *)key;


- (instancetype)initWithPrivateKey:(NSData *)key;


- (NSData *)publicKeyCompressed:(KeyCompression)compression;


@end




@interface ExtendedKeySecp256k1 : NSObject


@property (nonatomic, readonly, nonnull) NSData* prefixPub;


@property (nonatomic, readonly, nonnull) NSData* prefixPrv;


@property (nonatomic, readonly, copy, nonnull) KeySecp256k1 *key;


@property (nonatomic, readonly, copy, nonnull) NSData *chaincode;


@property (nonatomic, readonly, assign) int depth;


@property (nonatomic, readonly, assign) int parent;


@property (nonatomic, readonly, assign) int sequence;


- (instancetype)initWithSerializedString:(NSString *)string type:(KeyType)type;


- (instancetype)initWithSerializedData:(NSData *)data type:(KeyType)type;


- (instancetype)initWithKey:(KeySecp256k1 *)key chaincode:(NSData *)chaincode;


- (instancetype)initWithKey:(KeySecp256k1 *)key chaincode:(NSData *)chaincode prefixPub:(NSData *)prefixPub prefixPrv:(NSData *)prefixPrv;


- (instancetype)initWithExtendedKey:(ExtendedKeySecp256k1 *)key;


- (NSString *)serializedPub;


- (NSString *)serializedPrv;


- (NSString *)serializedString;


- (NSData *)serializedData;


- (void)derived:(uint32_t)sequence hardened:(BOOL)hardened;


@end


NS_ASSUME_NONNULL_END


#endif /* KeySecp256k1_h */
