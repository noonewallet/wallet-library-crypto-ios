//
//  KeyEd25519.m
//  WalletLibCrypto
//
//

#import "KeyEd25519.h"

#include "openssl/ec.h"
#include <openssl/hmac.h>

#include <CommonCrypto/CommonCrypto.h>
#import "Hash.h"

#include "ed25519.h"
#include "sign.h"


@interface KeyEd25519 ()


@property (nonatomic, readonly, nullable) NSData *key;


@end




@implementation KeyEd25519


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
    
    KeyEd25519 *cpy = [KeyEd25519 allocWithZone:zone];
    
    switch (_type) {
        case Public:
            
            return [cpy initWithPublicKey:_key];
            
        case Private:
            
            return [cpy initWithPrivateKey:_key];
    }
}


- (NSData *)publicKey {
    
    static const size_t keyLen = 32;
    unsigned char data[keyLen];
    
    switch (_type) {
        case Public:
            
            return _key;
            
        case Private:
            
            memset(data, 0, keyLen);
            
            cardano_crypto_ed25519_publickey([_key bytes], data);
            
            NSMutableData *output = [NSMutableData dataWithBytes:data length:keyLen];
            
            return output;
            
    }
}


- (NSData *)publicKeyED25519 {
    
    static const size_t keyLen = 32;
    unsigned char data[keyLen];
    
    switch (_type) {
        case Public:
            
            return _key;
            
        case Private:
            
            memset(data, 0, keyLen);
            
            size_t len = 32;
            
            EVP_PKEY *k = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL ,[_key bytes], [_key length]);
            
            EVP_PKEY_get_raw_public_key(k, data, &len);
            
            EVP_PKEY_free(k);
            
            NSMutableData *output = [NSMutableData dataWithBytes:data length:len];
            
            return output;
            
    }
}


@end




@implementation ExtendedKeyEd25519


- (instancetype)initWithKey:(KeyEd25519 *)key chaincode:(NSData *)chaincode {
    
    if (self = [super init]) {
        
        _key = [key copy];
        _depth = 0;
        _parent = 0;
        _sequence = 0;
        
        _chaincode = [chaincode copy];
        
    }
    
    return self;
}


- (instancetype)initWithKey:(KeyEd25519 *)key chaincode:(NSData *)chaincode depth:(int)depth parent:(int)parent sequence:(int)sequence {
    
    if (self = [super init]) {
        
        _key = [key copy];
        _depth = depth;
        _parent = parent;
        _sequence = sequence;
        
        _chaincode = [chaincode copy];
        
    }
    
    return self;
}


- (instancetype)initWithExtendedKeyEd25519:(ExtendedKeyEd25519 *)key {
    
    if (self = [super init]) {
        
        _key = [key.key copy];
        _depth = key.depth;
        _parent = key.parent;
        _sequence = key.sequence;
        
        _chaincode = key.chaincode;
        
    }
    
    return self;
}


- (uint32_t)parent_uint32 {
    
        uint32_t *words = (uint32_t *)[[self fingerprint] bytes];
        uint32_t parent = OSSwapBigToHostInt32(words[0]);
    
        return parent;
}


- (NSData *)fingerprint {
    
    return [Hash ripemd160Sha256From:[_key publicKey]];
}


- (void)derive:(uint32_t)sequence hardened:(BOOL)hardened {
    
    // calculate Z
    uint32_t __sequence = OSSwapHostToBigInt32(hardened ? (0x80000000 | sequence) : sequence);
    uint8_t index[4];
    index[0] = __sequence >> 24;
    index[1] = __sequence >> 16;
    index[2] = __sequence >> 8;
    index[3] = __sequence;
    
    static const int privateKeyLength = 64;
    static const int ccLength = 32;
    
    unsigned char prvKey[privateKeyLength];
    memcpy(prvKey, [_key bytes], [_key.data length]);
    
    unsigned char derivedKey[privateKeyLength];
    memset(derivedKey, 0, privateKeyLength);
    
    NSData *pubKey = _key.publicKey;
    
    HMAC_CTX *ctx = HMAC_CTX_new();
    HMAC_Init_ex(ctx, [_chaincode bytes], (int)[_chaincode length], EVP_sha512(), nil);
    
    if (hardened) {
        
        HMAC_Update(ctx, (const unsigned char *)TAG_DERIVE_Z_HARDENED, 1);
        HMAC_Update(ctx, [_key bytes], [_key.data length]);
        
    } else {
        
        HMAC_Update(ctx, (const unsigned char *)TAG_DERIVE_Z_NORMAL, 1);
        HMAC_Update(ctx, [pubKey bytes], [pubKey length]);
        
    }
    
    unsigned int sha512DigestLength = CC_SHA512_DIGEST_LENGTH;

    unsigned char z[sha512DigestLength];
    memset(z, 0, sizeof(z));
    
    HMAC_Update(ctx, index, 4);
    HMAC_Final(ctx, z, &sha512DigestLength);
    
    add_left(derivedKey, z, prvKey, 2);
    add_right(derivedKey, z, prvKey, 2);
    
    HMAC_CTX_reset(ctx);
    HMAC_Init_ex(ctx, [_chaincode bytes], (int)[_chaincode length], EVP_sha512(), nil);
    
    if (hardened) {
        
        HMAC_Update(ctx, (const unsigned char *)TAG_DERIVE_CC_HARDENED, 1);
        HMAC_Update(ctx, [_key bytes], [_key.data length]);
        
    } else {
        
        HMAC_Update(ctx, (const unsigned char *)TAG_DERIVE_CC_NORMAL, 1);
        HMAC_Update(ctx, [pubKey bytes], [pubKey length]);
        
    }

    unsigned char output[sha512DigestLength];
    memset(output, 0, sizeof(output));
    
    HMAC_Update(ctx, index, 4);
    HMAC_Final(ctx, output, &sha512DigestLength);
    
    HMAC_CTX_free(ctx);
    
    NSData *derivedCC = [NSData dataWithBytes:output + CC_SHA512_DIGEST_LENGTH/2 length:ccLength];
    
    _key = [[KeyEd25519 alloc] initWithPrivateKey: [NSData dataWithBytes:derivedKey length:privateKeyLength]];
    _chaincode = derivedCC;
    
    _depth += 1;
    _sequence = OSSwapBigToHostInt32(__sequence);
}


@end
