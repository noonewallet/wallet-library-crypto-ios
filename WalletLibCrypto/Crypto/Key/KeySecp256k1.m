//
//  KeySecp256k1.m
//  WalletLibCrypto
//
//

#import "KeySecp256k1.h"
#import <Bignum.h>
#import <Curve.h>
#import "Base58.h"

#include "openssl/ec.h"
#include <openssl/hmac.h>

#include <CommonCrypto/CommonCrypto.h>
#import "Hash.h"


unsigned char SLIP0132_DEFAULT_PUB_PREFIX[] = { 0x04, 0x88, 0xB2, 0x1E };
unsigned char SLIP0132_DEFAULT_PRV_PREFIX[] = { 0x04, 0x88, 0xAD, 0xE4 };




@interface KeySecp256k1 ()


@property (nonatomic, readonly, nullable) NSData *key;


@end




@implementation KeySecp256k1


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
    
    KeySecp256k1 *cpy = [KeySecp256k1 allocWithZone:zone];
    
    switch (_type) {
        case Public:
            
            return [cpy initWithPublicKey:_key];
            
        case Private:
            
            return [cpy initWithPrivateKey:_key];
    }
}


- (NSData *)publicKey {
    
    switch (_type) {
        case Public:
            
            return _key;
            
        case Private:
            
            return [self publicKeyCompressed:CompressedConversion];
    }
}


- (NSData *)publicKeyCompressed:(KeyCompression)compression {
    
    Curve *curve = [[Curve alloc] init];
    int conversion;
    
    switch (compression) {
        case CompressedConversion:
            
            conversion = POINT_CONVERSION_COMPRESSED;
            break;
            
        case UncompressedConversion:
            
            conversion = POINT_CONVERSION_UNCOMPRESSED;
            break;
    }
    
    int size = 0;
    unsigned char *data = NULL;
    
    [curve getPublicKey:[_key bytes] compressed:conversion output:&data size:&size];
    
    NSMutableData *output = [NSMutableData dataWithBytes:data length:size];

    OPENSSL_free(data);
    
    return output;
}

@end




@implementation ExtendedKeySecp256k1


- (instancetype)initWithKey:(KeySecp256k1 *)key chaincode:(NSData *)chaincode {
    
    if (self = [super init]) {
        
        _key = [key copy];
        _depth = 0;
        _parent = 0;
        _sequence = 0;
        
        _chaincode = [chaincode copy];
        
        _prefixPub = [NSData dataWithBytes:SLIP0132_DEFAULT_PUB_PREFIX length:4];
        _prefixPrv = [NSData dataWithBytes:SLIP0132_DEFAULT_PRV_PREFIX length:4];
        
    }
    
    return self;
}


- (instancetype)initWithKey:(KeySecp256k1 *)key chaincode:(NSData *)chaincode prefixPub:(NSData *)prefixPub prefixPrv:(NSData *)prefixPrv {
    
    if (self = [super init]) {
        
        _key = [key copy];
        _depth = 0;
        _parent = 0;
        _sequence = 0;
    
        _chaincode = [chaincode copy];
        
        _prefixPub = prefixPub;
        _prefixPrv = prefixPrv;
        
    }
    
    return self;
}


- (instancetype)initWithKey:(KeySecp256k1 *)key chaincode:(NSData *)chaincode depth:(int)depth parent:(int)parent sequence:(int)sequence {
    
    if (self = [super init]) {
        
        _key = [key copy];
        _depth = depth;
        _parent = parent;
        _sequence = sequence;
        
        _chaincode = [chaincode copy];
        
        _prefixPub = [NSData dataWithBytes:SLIP0132_DEFAULT_PUB_PREFIX length:4];
        _prefixPrv = [NSData dataWithBytes:SLIP0132_DEFAULT_PRV_PREFIX length:4];
        
    }
    
    return self;
}


- (instancetype)initWithKey:(KeySecp256k1 *)key chaincode:(NSData *)chaincode depth:(int)depth parent:(int)parent sequence:(int)sequence prefixPub:(NSData *)prefixPub prefixPrv:(NSData *)prefixPrv {
    
    if (self = [super init]) {
        
        _key = [key copy];
        _depth = depth;
        _parent = parent;
        _sequence = sequence;
        
        _chaincode = [chaincode copy];
        
        _prefixPub = prefixPub;
        _prefixPrv = prefixPrv;
        
    }
    
    return self;
}


- (instancetype)initWithExtendedKey:(ExtendedKeySecp256k1 *)key {
    
    if (self = [super init]) {
        
        _key = [key.key copy];
        _depth = key.depth;
        _parent = key.parent;
        _sequence = key.sequence;
        
        _chaincode = key.chaincode;
        
        _prefixPub = key.prefixPub;
        _prefixPrv = key.prefixPrv;
        
    }
    
    return self;
}


- (instancetype)initWithSerializedString:(NSString *)string type:(KeyType)type {
    
    return [self initWithSerializedData:[Base58 decodeUsedChecksum:string] type:type];
}


- (instancetype)initWithSerializedData:(NSData *)data type:(KeyType)type {
    
    if (self = [super init]) {
        
        if ([data length] != 78) {
            
            return nil;
            
        }
        
        unsigned char *bytes = (unsigned char *)[data bytes];
        
        BOOL hasPrivate;
        
        switch (type) {
            case Private:
                
                _prefixPrv = [data subdataWithRange:NSMakeRange(0, 4)];
                hasPrivate = YES;
                break;
                
            case Public:
                
                _prefixPub = [data subdataWithRange:NSMakeRange(0, 4)];
                hasPrivate = NO;
                break;
                
            default:
                
                return nil;
        }
                
        int depth = bytes[4] & 0xff;
        
        int parent = OSSwapBigToHostInt32(*(uint32_t *)(bytes + 5));
        int sequence = OSSwapBigToHostInt32(*(uint32_t *)(bytes + 9));
        
        NSData *chain = [NSData dataWithBytes:bytes + 13 length:32];
        NSData *prvOrPub = [NSData dataWithBytes:bytes + 13 + 32 length:33];
        
        if (hasPrivate) {
            
            _key = [[KeySecp256k1 alloc] initWithPrivateKey:[prvOrPub subdataWithRange:NSMakeRange(1, 32)]];
            
        } else {
            
            _key = [[KeySecp256k1 alloc] initWithPublicKey:prvOrPub];
            
        }
        
        _depth = depth;
        _sequence = sequence;
        _parent = parent;
        _chaincode = chain;
        
    }
    
    return self;
}


- (NSData *)serializedPubData {
    
    KeySecp256k1 *pkey = [[KeySecp256k1 alloc] initWithPublicKey:[_key publicKey]];
    
    ExtendedKeySecp256k1 *pubk = [[ExtendedKeySecp256k1 alloc] initWithKey:pkey chaincode:_chaincode depth:_depth parent:_parent sequence:_sequence prefixPub:_prefixPub prefixPrv:_prefixPrv];
    
    return [pubk serializedData];
}


- (NSData *)serializedPrvData {
    
    return [self serializedData];
}


- (NSString *)serializedPub {
    
    switch (_key.type) {
        case Public:
            
            return [Base58 encodeUsedChecksum:[self serializedData]];
            
        case Private:
            
            return [Base58 encodeUsedChecksum:[self serializedPubData]];
    }
}


- (NSString *)serializedPrv {
    
    return [Base58 encodeUsedChecksum:[self serializedPrvData]];
}


- (uint32_t)parent_uint32 {
    
        uint32_t *words = (uint32_t *)[[self fingerprint] bytes];
        uint32_t parent = OSSwapBigToHostInt32(words[0]);
    
        return parent;
}


- (NSData *)fingerprint {
    
    return [Hash ripemd160Sha256From:[_key publicKey]];
}


- (NSData *)serializedData {
    
    int length = 78;
    
    unsigned char bytes[length];
    memset(bytes, 0, length);
    
    bytes[4] = _depth & 0xff;
    
    uint32_t __parent = OSSwapHostToBigInt32(_parent);
    memcpy(bytes + 5, &__parent, sizeof(__parent));
    
    uint32_t __sequence = OSSwapHostToBigInt32(_sequence);
    memcpy(bytes + 9, &__sequence, sizeof(__sequence));
    
    memcpy(bytes + 13, [_chaincode bytes], 32);
    
    const unsigned char *bytesPrefixPub = [_prefixPub bytes];
    const unsigned char *bytesPrefixPrv = [_prefixPrv bytes];
    
    switch (_key.type) {
        case Public:
            
            bytes[0] = bytesPrefixPub[0];
            bytes[1] = bytesPrefixPub[1];
            bytes[2] = bytesPrefixPub[2];
            bytes[3] = bytesPrefixPub[3];
            
            memcpy(bytes + 45, [_key bytes], _key.key.length);
            break;
            
        case Private:
            
            bytes[0] = bytesPrefixPrv[0];
            bytes[1] = bytesPrefixPrv[1];
            bytes[2] = bytesPrefixPrv[2];
            bytes[3] = bytesPrefixPrv[3];
            
            memcpy(bytes + 46, [_key bytes], _key.key.length);
            break;
    }
    
    return [NSData dataWithBytes:bytes length:length];
}


- (NSString *)serializedString {
    
    return [Base58 encodeUsedChecksum:[self serializedData]];
}


- (void)derived:(uint32_t)sequence hardened:(BOOL)hardened {
    
    if (_key.type == Public && hardened) {
        
        return;
        
    }
    
    unsigned char bytes[33 + 4];
    memset(bytes, 0, sizeof(bytes));
    
    unsigned char *privateKeyData = (unsigned char *)[_key bytes];
    
    if (_key.type == Private && hardened) {
        
        memcpy(bytes + 1, privateKeyData, 32);
        
    } else {
        
        unsigned char *pub = (unsigned char *)[[_key publicKey] bytes];
        memcpy(bytes, pub, 33);
        
    }
    
    uint32_t __sequence = OSSwapHostToBigInt32(hardened ? (0x80000000 | sequence) : sequence);
    memcpy(bytes + 33, &__sequence, sizeof(__sequence));
    
    unsigned int sha512DigestLength = CC_SHA512_DIGEST_LENGTH;
    
    unsigned char factorData[sha512DigestLength];
    memset(factorData, 0, sizeof(factorData));
    
    HMAC(EVP_sha512(), [_chaincode bytes], (int)[_chaincode length], bytes, 33 + 4, factorData, &sha512DigestLength);
    
    Bignum *order = [[[Curve alloc] init] order];
    Bignum *factor = [[Bignum alloc] init:factorData length:32];
    
    if ([factor compare:order] >= 0) {
        
        return;
        
    }
    
    NSData *derivedChainCode = [NSData dataWithBytes:factorData + 32 length:32];
    
    _parent = [self parent_uint32];
    
    if (_key.type == Private) {
        
        Bignum *bn = [[Bignum alloc] init:privateKeyData length:32];
        [Bignum sum:bn rvalue:factor mod:order result:bn];
        
        if (bn.isZero) {
            
            return;
            
        }
        
        NSMutableData *output = [NSMutableData dataWithLength:32];
        [bn makeBin:output.mutableBytes len:32];
        
        _key = [[KeySecp256k1 alloc] initWithPrivateKey:output];
        _chaincode = derivedChainCode;

    } else {
        
        Curve *curve = [[Curve alloc] init];

        CurvePoint *point = [[CurvePoint alloc] init:curve pointConversion:POINT_CONVERSION_COMPRESSED];
        [point setPointWithData:[_key publicKey] curve:curve];

        [point mul:factor curve:curve];

        if ([point isAtInfinity:curve] == 1) {
            
            return;
            
        }

        _key = [[KeySecp256k1 alloc] initWithPublicKey:[point data]];
        _chaincode = derivedChainCode;
        
    }
    
    _depth += 1;
    _sequence = OSSwapBigToHostInt32(__sequence);
}

@end

