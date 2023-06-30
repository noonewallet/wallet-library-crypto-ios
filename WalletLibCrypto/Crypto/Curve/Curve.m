//
//  Curve.m
//  WalletLibCrypto
//
//

#import "Curve.h"
#import "Bignum.h"


#import <openssl/ec.h>
#import <openssl/ecdh.h>
#import <openssl/ecdsa.h>
#import <openssl/evp.h>
#import <openssl/bn.h>


typedef struct {
    EC_KEY *eckey;
    const EC_GROUP *ecgroup;
    EC_POINT *ecpoint;
} CurveContext;




@interface CurvePoint ()


@property (nonatomic, nonnull) NSData *point;


@end




@implementation CurvePoint


- (instancetype)init:(Curve *)curve pointConversion:(int)conversion {
    
    if (self = [super init]) {
        
        _point = [curve newPointConversion:conversion];
        
    }
    
    return self;
}


- (int)isAtInfinity:(Curve *)curve {
    
    return [curve isAtInfinityPoint:self];
}


- (void)setPointWithData:(NSData *)data curve:(Curve *)curve {
    
    _point = [curve newPoint:data conversion:POINT_CONVERSION_COMPRESSED];
}


- (void)mul:(Bignum *)factor curve:(Curve *)curve {
    
    _point = [curve multiply:self factor:factor];
}


- (NSData *)data {
    
    return _point;
}


@end




@interface Curve ()


@property (nonatomic, nonnull)  CurveContext *context;


@end




@implementation Curve


- (instancetype)init {
    
    if (self = [super init]) {
        
        _context = malloc(sizeof(CurveContext));
        _context->eckey = EC_KEY_new_by_curve_name(NID_secp256k1);
        _context->ecgroup = EC_KEY_get0_group(_context->eckey);
        _context->ecpoint = NULL;
        
    }
    
    return self;
}


- (instancetype)initBignum:(Bignum *)bignum {
    
    if (self = [super init]) {
        
        _context = malloc(sizeof(CurveContext));
        _context->eckey = EC_KEY_new_by_curve_name(NID_secp256k1);
        _context->ecgroup = EC_KEY_get0_group(_context->eckey);
        _context->ecpoint = EC_POINT_new(_context->ecgroup);
        
        unsigned char *bin = bignum.bin;
        
        BIGNUM *bn = BN_new();
        BN_bin2bn(bin, 32, bn);
        EC_POINT_mul(_context->ecgroup, _context->ecpoint, bn, NULL, NULL, NULL);
        
        EC_KEY_set_public_key(_context->eckey, _context->ecpoint);
        EC_KEY_set_private_key(_context->eckey, bn);
        
        BN_free(bn);
        OPENSSL_free(bin);
        
    }
    
    return self;
}


- (instancetype)initX:(Bignum *)x yBit:(int)yBit {
    
    if (self = [super init]) {
        
        _context = malloc(sizeof(CurveContext));
        _context->eckey = EC_KEY_new_by_curve_name(NID_secp256k1);
        _context->ecgroup = EC_KEY_get0_group(_context->eckey);
        _context->ecpoint = EC_POINT_new(_context->ecgroup);
        
        unsigned char *bin = x.bin;
        
        BIGNUM *bn = BN_new();
        BN_bin2bn(bin, 32, bn);
        
        EC_POINT_set_compressed_coordinates_GFp(_context->ecgroup, _context->ecpoint, bn, yBit, NULL);
        
        BN_free(bn);
        OPENSSL_free(bin);
        
    }
    
    return self;
}


- (NSData *)multiply:(CurvePoint *)point factor:(Bignum *)factor {
    
    BIGNUM *f = BN_new();
    BIGNUM *bnp = BN_new();

    EC_POINT *p = EC_POINT_new(_context->ecgroup);
    BN_bin2bn([point.point bytes], (int)point.point.length, bnp);

    EC_POINT_bn2point(_context->ecgroup, bnp, p, NULL);

    BN_bin2bn(factor.bin, factor.numBytes, f);

    BN_CTX *ctx = BN_CTX_new();
    EC_POINT_mul(_context->ecgroup, p, f, p, BN_value_one(), ctx);

    BN_zero(bnp);
    EC_POINT_point2bn(_context->ecgroup, p, POINT_CONVERSION_COMPRESSED, bnp, ctx);
    
    unsigned char *bin = calloc(BN_num_bytes(bnp), sizeof(char));
    
    BN_bn2bin(bnp, bin);
    
    NSData *result = [NSData dataWithBytes:bin length:BN_num_bytes(bnp)];

    EC_POINT_clear_free(p);
    BN_free(f);
    BN_free(bnp);
    BN_CTX_free(ctx);
    
    OPENSSL_free(bin);
    
    return result;
}


- (Bignum *)order {
    
    BIGNUM *bn = BN_new();
    EC_GROUP_get_order(_context->ecgroup, bn, NULL);
    unsigned char data[BN_num_bytes(bn)];
    memset(data, 0, sizeof(data));

    BN_bn2bin(bn, data);
    BN_free(bn);
    
    return [[Bignum alloc] init:data length:(int)sizeof(data)];
}


- (int)degree {
    
    return EC_GROUP_get_degree(_context->ecgroup);
}


- (NSData *)newPointConversion:(int)conversion {
    
    EC_POINT *p = EC_POINT_new(_context->ecgroup);
    BIGNUM *bn = BN_new();
    
    EC_POINT_point2bn(_context->ecgroup, p, conversion, bn, NULL);
    
    unsigned char *bin = calloc(BN_num_bytes(bn), sizeof(char));
    
    BN_bn2bin(bn, bin);
    
    NSData *result = [NSData dataWithBytes:bin length:BN_num_bytes(bn)];
    
    BN_free(bn);
    EC_POINT_clear_free(p);

    OPENSSL_free(bin);
    
    return result;
}


- (NSData *)newPoint:(NSData *)data conversion:(int)conversion {
    
    EC_POINT *p = EC_POINT_new(_context->ecgroup);
    BIGNUM *bn = BN_new();

    BN_bin2bn(data.bytes, (int)data.length, bn);
    EC_POINT_bn2point(_context->ecgroup, bn, p, NULL);
    
    BN_zero(bn);
    EC_POINT_point2bn(_context->ecgroup, p, conversion, bn, NULL);
    
    unsigned char *bin = calloc(BN_num_bytes(bn), sizeof(char));
    
    BN_bn2bin(bn, bin);
    
    NSData *result = [NSData dataWithBytes:bin length:BN_num_bytes(bn)];
    
    EC_POINT_clear_free(p);
    BN_free(bn);
    
    OPENSSL_free(bin);

    return result;
}


- (int)isAtInfinityPoint:(CurvePoint *)point  {
    
    EC_POINT *p = EC_POINT_new(_context->ecgroup);
    BIGNUM *bn = BN_new();
    
    BN_bin2bn([point.point bytes], (int)point.point.length, bn);
    
    EC_POINT_bn2point(_context->ecgroup, bn, p, NULL);
    
    int result = EC_POINT_is_at_infinity(_context->ecgroup, p);
    
    EC_POINT_clear_free(p);
    BN_free(bn);
    
    return result;
}


- (void)recoveryPublicKeyU1:(Bignum *)u1 U2:(Bignum *)u2 compression:(int)compressionConversion data:(unsigned char**)data size:(int *)size {
    
    EC_POINT *Q = EC_POINT_new(_context->ecgroup);
    unsigned char *u1bin = u1.bin;
    unsigned char *u2bin = u2.bin;
    
    BIGNUM *bnu1 = BN_bin2bn(u1bin, u1.numBytes, NULL);
    BIGNUM *bnu2 = BN_bin2bn(u2bin, u2.numBytes, NULL);
    EC_POINT_mul(_context->ecgroup, Q, bnu1, _context->ecpoint, bnu2, NULL);
    
    size_t expected_size = EC_POINT_point2oct(_context->ecgroup, Q, compressionConversion, NULL, 0, NULL);
    *data = calloc(expected_size, sizeof(char));
    
    BN_free(bnu1);
    BN_free(bnu2);
    
    OPENSSL_free(u1bin);
    OPENSSL_free(u2bin);
    
    EC_POINT_point2oct(_context->ecgroup, Q, compressionConversion, *data, expected_size, NULL);
    
    EC_POINT_free(Q);
    *size = (int)expected_size;
}


- (int)ecdsaVerifySignature:(NSData *)signature forHash:(NSData *)hash; {
    
    return ECDSA_verify(0,
                        (unsigned char *)hash.bytes,
                        (int)hash.length,
                        (unsigned char*)signature.bytes,
                        (int)signature.length, _context->eckey);
}


- (Bignum *)xPoint:(Bignum *)point {
    
    unsigned char *bin = point.bin;
    
    BIGNUM *mult = BN_bin2bn(bin, 32, NULL);
    BIGNUM *bnx = BN_new();
    
    EC_POINT *K = EC_POINT_new(_context->ecgroup);
    EC_POINT_copy(K, EC_GROUP_get0_generator(_context->ecgroup));
    EC_POINT_mul(_context->ecgroup, K, NULL, K, mult, NULL);
    EC_POINT_get_affine_coordinates_GFp(_context->ecgroup, K, bnx, NULL, NULL);
    
    int length = BN_num_bytes(bnx);
    
    unsigned char bytes[length];
    memset(bytes, 0, sizeof(bytes));
    
    BN_bn2bin(bnx, bytes);
    EC_POINT_free(K);
    
    BN_free(mult);
    BN_free(bnx);
    
    OPENSSL_free(bin);
    
    return [[Bignum alloc] init:bytes length:length];
}


- (Bignum *)yPoint:(Bignum *)point {
    
    unsigned char *bin = point.bin;
    
    BIGNUM *mult = BN_bin2bn(bin, 32, NULL);
    BIGNUM *bny = BN_new();
    
    EC_POINT *K = EC_POINT_new(_context->ecgroup);
    EC_POINT_copy(K, EC_GROUP_get0_generator(_context->ecgroup));
    EC_POINT_mul(_context->ecgroup, K, NULL, K, mult, NULL);
    EC_POINT_get_affine_coordinates_GFp(_context->ecgroup, K, NULL, bny, NULL);
    
    unsigned char bytes[BN_num_bytes(bny)];
    memset(bytes, 0, sizeof(bytes));
    
    BN_bn2bin(bny, bytes);
    
    EC_POINT_free(K);
    BN_free(mult);
    BN_free(bny);
    
    OPENSSL_free(bin);
    
    return [[Bignum alloc] init:bytes length:(int)sizeof(bytes)];
}


- (void)getPublicKey:(const unsigned char*)key compressed:(int)compressed output:(unsigned char **)output size:(int *)size {
    
    BN_CTX *bnctx = BN_CTX_new();
    BIGNUM *bn = BN_CTX_get(bnctx);
    
    BN_bin2bn(key, 32, bn);
    
    EC_POINT *publicKey = EC_POINT_new(_context->ecgroup);
    EC_POINT_mul(_context->ecgroup, publicKey, bn, NULL, NULL, bnctx);
    
    EC_KEY_set_private_key(_context->eckey, bn);
    EC_KEY_set_public_key(_context->eckey, publicKey);

    EC_KEY_set_conv_form(_context->eckey, compressed);
    
    size_t expected_size = i2o_ECPublicKey(_context->eckey, NULL);
    i2o_ECPublicKey(_context->eckey, output);
    
    *size = (int)expected_size;
    BN_CTX_free(bnctx);
    EC_POINT_free(publicKey);
}


- (void)dealloc {
    
    EC_KEY_free(_context->eckey);
    
    if (_context->ecpoint) {
        
        EC_POINT_clear_free(_context->ecpoint);
        
    }
    
    OPENSSL_free(_context);
}


@end
