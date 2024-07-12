//
//  KeyTweetNacl.m
//  WalletLibCrypto
//
//


#import "KeyTweetNacl.h"
#import "KeyType.h"

#include "TweetNacl.h"


@interface KeyTweetNacl ()


@property (nonatomic, readonly, nullable) NSData *key;


@end




@implementation KeyTweetNacl


- (instancetype)initWithPrivateKey:(NSData *)key {
    
    if (self = [super init]) {
        
        _type = Private;
        _key = key;
        
    }
    
    return self;
}


- (instancetype)initWithPublicKey:(NSData *)key {
    
    if (self = [super init]) {
        
        _type = Public;
        _key = key;
        
    }
    
    return self;
}


- (const void *)bytes {
    
    return [_key bytes];
}


- (NSData *)data {
    
    return _key;
}


- (id)copyWithZone:(NSZone *)zone {
    
    KeyTweetNacl *cpy = [KeyTweetNacl allocWithZone:zone];
    
    switch (_type) {
        case Public:
            
            return [cpy initWithPublicKey:_key];
            
        case Private:
            
            return [cpy initWithPrivateKey:_key];
    }
}


- (NSData *)publicKey {
    
    unsigned char data[32];
    
    switch (_type) {
        case Public:
            
            return _key;
            
        case Private:
            
            memset(data, 0, 32);
            
            unsigned char *p = (unsigned char *)[_key bytes];
            
            crypto_sign_ed25519_tweet_keypair(data, p);
            
            NSMutableData *output = [NSMutableData dataWithBytes:data length:32];
            
            return output;
    }
}


@end
