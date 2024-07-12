//
//  KeyTweetNacl.h
//  WalletLibCrypto
//
//

#ifndef KeyTweetNacl_h
#define KeyTweetNacl_h

#import <Foundation/Foundation.h>
#import "KeyType.h"


NS_ASSUME_NONNULL_BEGIN


@interface KeyTweetNacl : NSObject <NSCopying>


@property (nonatomic, readonly, assign) KeyType type;


@property (nonatomic, readonly, nonnull) NSData *data;


- (instancetype)initWithPublicKey:(NSData *)key;


- (instancetype)initWithPrivateKey:(NSData *)key;


- (NSData *)publicKey;


@end


NS_ASSUME_NONNULL_END

#endif /* KeyTweetNacl_h */
