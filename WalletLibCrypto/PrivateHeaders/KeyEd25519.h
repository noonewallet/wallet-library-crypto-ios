//
//  KeyEd25519.h
//  WalletLibCrypto
//
//

#ifndef KeyEd25519_h
#define KeyEd25519_h

#import <Foundation/Foundation.h>
#import "KeyType.h"


NS_ASSUME_NONNULL_BEGIN


@interface KeyEd25519 : NSObject <NSCopying>


@property (nonatomic, readonly, assign) KeyType type;


@property (nonatomic, readonly, nonnull) NSData *data;


- (instancetype)initWithPublicKey:(NSData *)key;


- (instancetype)initWithPrivateKey:(NSData *)key;


- (NSData *)publicKey;


- (NSData *)publicKeyED25519;


+ (BOOL)isOnCurveTweetNaclED25519:(NSData *)key;


@end




@interface ExtendedKeyEd25519 : NSObject


@property (nonatomic, readonly, copy, nonnull) KeyEd25519 *key;


@property (nonatomic, readonly, copy, nonnull) NSData *chaincode;


@property (nonatomic, readonly, assign) int depth;


@property (nonatomic, readonly, assign) int parent;


@property (nonatomic, readonly, assign) int sequence;


- (instancetype)initWithKey:(KeyEd25519 *)key chaincode:(NSData *)chaincode;


- (instancetype)initWithExtendedKeyEd25519:(ExtendedKeyEd25519 *)key;


- (void)derive:(uint32_t)sequence hardened:(BOOL)hardened;


@end


NS_ASSUME_NONNULL_END


#endif /* KeyEd25519_h */
