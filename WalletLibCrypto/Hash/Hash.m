//
//  Hash.m
//  WalletLibCrypto
//
//

#import "Hash.h"
#import <openssl/ripemd.h>
#import <keccak-tiny.h>

#include <CommonCrypto/CommonCrypto.h>

#include "blake2b.h"


@implementation Hash


+ (nonnull NSData *)keccak256From:(nonnull NSData *)data {
    
    const uint8_t *input = [data bytes];
    uint8_t output[32];
    memset(output, 0, sizeof(output));
    
    sha3_256(output, 32, input, (size_t)data.length);
    
    return [NSData dataWithBytes:output length:32];
}


+ (nonnull NSData *)ripemd160From:(nonnull NSData *)data {
    
    unsigned char output[RIPEMD160_DIGEST_LENGTH];
    __block RIPEMD160_CTX ctx;
    RIPEMD160_Init(&ctx);
    
    [data enumerateByteRangesUsingBlock:^(const void * _Nonnull bytes, NSRange byteRange, BOOL * _Nonnull stop) {
        RIPEMD160_Update(&ctx, bytes, byteRange.length);
    }];
    
    RIPEMD160_Final(output, &ctx);
    NSData *hash = [NSData dataWithBytes:output length:sizeof(output)];
    memset(output, 0, sizeof(output));
    
    return hash;
}


+ (nonnull NSData *)sha256From:(nonnull NSData *)data {
    
    unsigned char output[CC_SHA256_DIGEST_LENGTH];
    memset(output, 0, CC_SHA256_DIGEST_LENGTH);
    CC_SHA256([data bytes], (CC_LONG)[data length], output);
    
    NSData *hash = [NSData dataWithBytes:output length:CC_SHA256_DIGEST_LENGTH];
    memset(output, 0, sizeof(output));
    
    return hash;
}


+ (nonnull NSData *)sha256DoubleFrom:(nonnull NSData *)data {
    
    return [Hash sha256From:[Hash sha256From:data]];
}


+ (nonnull NSData *)blake2b256From:(nonnull NSData *)data {
    
    static const size_t outputLen = 32;

    uint8_t output[outputLen];
    memset(output, 0, outputLen);
    
    uint8_t *udata = (uint8_t *)[data bytes];
    size_t len = (size_t)[data length];
    
    blake2b(output, outputLen, NULL, 0, udata, len);

    NSData *hash = [NSData dataWithBytes:output length:outputLen];
    
    return hash;
}


+ (nonnull NSData *)blake2b224From:(nonnull NSData *)data {
    
    static const size_t outputLen = 28;

    uint8_t output[outputLen];
    memset(output, 0, outputLen);
    
    uint8_t *udata = (uint8_t *)[data bytes];
    size_t len = (size_t)[data length];
    
    blake2b(output, outputLen, NULL, 0, udata, len);

    NSData *hash = [NSData dataWithBytes:output length:outputLen];
    
    return hash;
}


+ (nonnull NSData *)ripemd160Sha256From:(nonnull NSData *)data {
    
    return  [Hash ripemd160From: [Hash sha256From:data]];
}


@end
