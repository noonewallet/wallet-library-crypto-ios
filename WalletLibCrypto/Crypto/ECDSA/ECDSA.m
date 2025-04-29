//
//  ECDSA.m
//  WalletLibCrypto
//
//

#import <Foundation/Foundation.h>

#import <ECDSA.h>
#import <Bignum.h>
#import <Curve.h>

#import <openssl/ec.h>

#include <CommonCrypto/CommonCrypto.h>


@implementation ECDSA


+(nonnull NSData *)sign:(NSData *)hash key:(NSData *)key noncetype:(NonceFunction)noncetype recid:(NSInteger *)recid outtype:(SignOutputType)outputType {
    
    NSData *nonce;
    NSData *signature;
    
    int counter = 0;
    
    switch (noncetype) {
        case RFC6979:
            
            nonce = [self noncerfc6979:hash key:key];
            signature = [self sign:hash key:key nonce:nonce recid:recid outputType:outputType];
            
            return signature;
            
        case EOS:
            
            do {
                nonce = [self nonceeosf:hash key:key counter:counter];
                
                signature = [self sign:hash key:key nonce:nonce recid:recid outputType:outputType];
                Bignum *r = [[Bignum alloc] init:signature.bytes length:32];
                Bignum *s = [[Bignum alloc] init:signature.bytes + 32 length:32];
                
                int failedR = ( r.isNegative == 0 ) && ( r.numBits >= 256 );
                int failedS = ( s.isNegative == 0 ) && ( s.numBits >= 256 );

                if (!failedR && !failedS) { break; }

                counter++;
                
            } while (YES);

            return signature;
    }
}


+ (BOOL)validateSignature:(NSData *)signature hash:(NSData *)hash forKey:(NSData *)key {
    
    if (hash.length == 0 || signature.length == 0) { return NO; }
    
    Bignum *bn = [[Bignum alloc] init:key.bytes length:32];
    Curve *curve = [[Curve alloc] initBignum:bn];

    int isValid = [curve ecdsaVerifySignature:signature forHash:hash];
    
    if (isValid == 1) {
        
        return YES;
        
    }
    
    return NO;
}


+ (BOOL)validateCompactSignature:(NSData *)compactSignature hash:(NSData *)hash forPublicKey:(NSData *)key {
    
    NSData * recoveredPubKey = [self recoveryPublicKeySignature:compactSignature hash:hash compression:Compressed];
    
    if ([key isEqualToData:recoveredPubKey]) {
        
        return YES;
        
    } else {
        
        return NO;
        
    }
}


+ (nullable NSData *)recoveryPublicKeySignature:(NSData *)compactSignature hash:(NSData *)hash compression:(enum PublickKeyCompressionType)compression {
    
    const unsigned char *signature_bytes = compactSignature.bytes;
    unsigned char v = signature_bytes[64];
    
    int rec_id = (v - 0x1b) & 0x01;
    
    ECDSA_SIG *ecdsa_sig = ECDSA_SIG_new();
   
    Bignum *x = [[Bignum alloc] init];
    Bignum *r = [[Bignum alloc] init:signature_bytes length:32];
    Bignum *s = [[Bignum alloc] init:signature_bytes + 32 length:32];
   
    Bignum *j = [Bignum zero];
    Bignum *n = [[[Curve alloc] init] order];

    [Bignum mul:j rvalue:n result:j];
    [Bignum sum:r rvalue:j result:x];
    
    //Calculate a curve point R
    Curve *curve = [[Curve alloc] initX:x yBit:rec_id];

    //Let e = HASH(m)
    int msglen = (int)hash.length;
    
    Bignum *z = [[Bignum alloc] init:hash.bytes length:msglen];
    int num_bits = curve.degree;
    
    //Let z, left most bits of e
    if (msglen * 8 > num_bits) {
        [z rshift:(8 - (num_bits & 7))];
    }
    
    Bignum *zero = [[Bignum alloc] init];
    //Set z negative
    [Bignum sub:zero rvalue:z mod:n result:z];
    
    Bignum *rmod = [[Bignum alloc] init];
    Bignum *u1 = [[Bignum alloc] init];
    Bignum *u2 = [[Bignum alloc] init];
    
    [Bignum modInverse:r mod:n result:rmod];
    // u1 = -z * r mod n
    [Bignum mul:rmod rvalue:z mod:n result:u1];
    // u2 = s * r mod n
    [Bignum mul:rmod rvalue:s mod:n result:u2];
    
    unsigned char *data = NULL;
    int size = 0;
    
    switch (compression) {
        case Compressed:
            
            [curve recoveryPublicKeyU1:u1 U2:u2 compression:POINT_CONVERSION_COMPRESSED data:&data size:&size];
            break;
            
        case Uncompressed:
            
            [curve recoveryPublicKeyU1:u1 U2:u2 compression:POINT_CONVERSION_UNCOMPRESSED data:&data size:&size];
            break;
            
    }
    
    ECDSA_SIG_free(ecdsa_sig);

    NSMutableData *pubData = [NSMutableData dataWithBytes:data length: size];
    
    OPENSSL_free(data);
    
    return pubData;
}


#pragma mark - Private

/// Generation 'k' deterministically from message 'data' and private key 'key'
/// @param data Input data
/// @param key Private key
+ (nullable NSData *)noncerfc6979:(NSData *)data key:(nonnull NSData *)key {
    
    int vLength = 32, kLength = 32, xLength = 32;
    int hLength = 32, tLength = 32;
    
    //Set V: V = 0x01 0x01 0x01 ... 0x01
    uint8_t v[vLength];
    memset(v, 1, sizeof(v));

    //Set K: K = 0x00 0x00 0x00 ... 0x00
    uint8_t k[kLength];
    memset(k, 0, sizeof(k));

    //Set K = HMAC_K( V 'concatenate' 0x00 'concatenate' int2octets(x) 'concatenate' bits2octets(h1) ) where h1 H(data)
    uint8_t buffer[vLength + 1 + xLength + hLength];
    memset(buffer, 0, sizeof(buffer));
    memcpy(buffer, v, sizeof(v));

    uint8_t x[xLength];
    memset(x, 0, sizeof(x));
    
    memcpy(x, key.bytes, sizeof(x));

    memcpy(buffer + vLength + 1, x, sizeof(x));
    
    Bignum *order = [[[Curve alloc] init] order];
    Bignum *hash = [[Bignum alloc] init:data.bytes length:32];
    [Bignum mod:hash mod:order];

    unsigned char h[hLength];
    memset(h, 0, hLength);

    [hash makeBin:h len:hLength];

    memcpy(buffer + vLength + 1 + xLength, h, hLength);

    CCHmac(kCCHmacAlgSHA256, k, sizeof(k), buffer, sizeof(buffer), k);

    //Set V: V = HMAC_K(V)
    CCHmac(kCCHmacAlgSHA256, k, sizeof(k), v, sizeof(v), v);

    memcpy(buffer, v, sizeof(v));
    memcpy(buffer + sizeof(v) + 1, x, sizeof(x));
    memcpy(buffer + sizeof(v) + sizeof(x) + 1, h, sizeof(h));

    memset(buffer + sizeof(v), 1, 1);

    CCHmac(kCCHmacAlgSHA256, k, sizeof(k), buffer, sizeof(buffer), k);
    CCHmac(kCCHmacAlgSHA256, k, sizeof(k), v, sizeof(v), v);
    
    // T
    uint8_t t[tLength];
    memset(t, 0, sizeof(t));

    Bignum *bn = [[Bignum alloc] init];

    while (YES) {
        
        CCHmac(kCCHmacAlgSHA256, k, sizeof(k), v, sizeof(v), t);
        bn = [[Bignum alloc] init:t length:tLength];

        BOOL isZero = bn.isZero != 1;
        BOOL lessThanOrder = [bn compare:order] == -1;

        if (isZero && lessThanOrder) {
            
            NSData *result = [[NSData alloc] initWithBytes:&t length:sizeof(t)];
            return result;
            
        } else {
            
            memcpy(buffer, v, sizeof(v));
            memset(buffer + sizeof(v), 0x00, 1);
            CCHmac(kCCHmacAlgSHA256, k, sizeof(k), buffer, sizeof(v) + 1, k);
            CCHmac(kCCHmacAlgSHA256, k, sizeof(k), v, sizeof(v), v);
            
        }
        
    }
}

+ (NSData *)nonceeosf:(NSData *)data key:(NSData *)key counter:(NSInteger)counter {
    const unsigned char *msg = (const unsigned char *)data.bytes;
    int hashLength = CC_SHA256_DIGEST_LENGTH;
    
    unsigned char hash[hashLength];
    memset(hash, 0, hashLength);
    
    int length = (int)data.length;
    
    if (counter == 0) {
        memcpy(hash, msg, length);
    } else {
        unsigned char *updatedHash = malloc(length + counter);
        memset(updatedHash, 0, length + counter);
        memcpy(updatedHash, msg, length);
        CC_SHA256(updatedHash, length + (int)counter, hash);
        
        OPENSSL_free(updatedHash);
    }
    
    NSData *k = [self noncerfc6979:[NSData dataWithBytes:hash length:hashLength] key:key];
    return k;
}

+(NSData *)serialize:(ECDSA_SIG *)signature recId:(NSInteger)recid forType:(SignOutputType)outputType {
    NSMutableData *result;
    
    switch (outputType) {
        case Compact:
            result = [NSMutableData dataWithLength:65];
            unsigned char *r = calloc(32, sizeof(char));
            unsigned char *s = calloc(32, sizeof(char));

            BIGNUM *bnr;
            BIGNUM *bns;

            ECDSA_SIG_get0(signature, (const BIGNUM **)&bnr, (const BIGNUM **)&bns);

            int roffset = 32 - BN_num_bytes(bnr);
            int soffset = 32 - BN_num_bytes(bns);
            
            BN_bn2bin(bnr, r + roffset);
            BN_bn2bin(bns, s + soffset);

            unsigned char v = 0x1b + recid + 4; /* PublicKey compressed */
            [result replaceBytesInRange:NSMakeRange(0, 32) withBytes:r length:32];
            [result replaceBytesInRange:NSMakeRange(32, 32) withBytes:s length:32];
            [result replaceBytesInRange:NSMakeRange(64, 1) withBytes:&v length: 1];

            BN_free(bnr);
            BN_free(bns);
            OPENSSL_free(r);
            OPENSSL_free(s);
            
            return result;
            
        case DER:
            result = [NSMutableData dataWithLength:90];
            
            unsigned char *p = (unsigned char*)result.mutableBytes;
            int size = i2d_ECDSA_SIG(signature, &p);
            
            [result setLength:size];
            return result;
    }
}

+ (NSData *)sign:(NSData *)hash key:(NSData *)key nonce:(NSData *)nonce recid:(NSInteger *)recid outputType:(enum SignOutputType)outputType {
    Curve *curve = [[Curve alloc] init];
    Bignum *order = [curve order];

    //Set private as BigNumber
    Bignum *KEY = [[Bignum alloc] init:key.bytes length:32];
    Bignum *k = [[Bignum alloc] init:nonce.bytes length:32];

    //Make sure what 'k' [0, n - 1]
    [Bignum mod:k mod:order];

    //Find x of K
    Bignum *KX = [curve xPoint:k];
    Bignum *KY = [curve yPoint:k];

    //Set BIGNUM for message 'data'
    Bignum *H = [[Bignum alloc] init:hash.bytes length:32];

    [Bignum mod:H mod:order];

    // S = (K^-1) * (H + (KX * KEY))
    Bignum *S = [[Bignum alloc] init];

    [Bignum mul:KX rvalue:KEY mod:order result:S];
    [Bignum sum:S rvalue:H mod:order result:S];
    [Bignum modInverse:k mod:order result:k];
    [Bignum mul:S rvalue:k mod:order result:S];

    Curve *curve2 = [[Curve alloc] initBignum:KEY];

    //Set order/2
    Bignum *N = [curve2 order];
    Bignum *halfOrder = [N rshifted:1];

    unsigned int rec_id = 0;
    rec_id = 0 | (KY.isOdd ? 1 : 0);

    if ([S compare:halfOrder] > 0) {
        [Bignum sub:N rvalue:S result:S];
        rec_id ^= 1;
    }

    if (recid) {
        *recid = rec_id;
    }

    ECDSA_SIG *ecdsaSig;
    ecdsaSig = ECDSA_SIG_new();

    BIGNUM *r = BN_new();
    BIGNUM *s = BN_new();

    unsigned char *kxBin = KX.bin;
    unsigned char *sBin = S.bin;
    
    BIGNUM *bnKX = BN_bin2bn(kxBin, 32, NULL);
    BIGNUM *bnS = BN_bin2bn(sBin, 32, NULL);
    
    OPENSSL_free(kxBin);
    OPENSSL_free(sBin);

    BN_copy(r, bnKX);
    BN_copy(s, bnS);

    ECDSA_SIG_set0(ecdsaSig, r, s);

    BN_free(bnKX);
    BN_free(bnS);

    return [self serialize:ecdsaSig recId:rec_id forType:outputType];
}


@end
