//
//  Bignum.m
//  WalletLibCrypto
//
//

#import "Bignum.h"
#include <openssl/bn.h>


@interface Bignum ()


@property (nonatomic, nonnull) BIGNUM *bn;


@end




@implementation Bignum


- (instancetype)init {
    
    if (self = [super init]) {
        
        BIGNUM *zero = BN_new();
        BN_zero(zero);
        
        _bn = zero;
    }
    
    return self;
}


- (instancetype)init:(Bignum *)bignum {
    
    if (self = [super init]) {
        
        _bn = bignum.bn;
        
    }
    
    return self;
}


- (instancetype)initHex:(const char *)hex {
    
    if (self = [super init]) {
    
        _bn = BN_new();
        BN_hex2bn(&_bn, hex);
        
    }
    
    return self;
}


- (instancetype)init:(const unsigned char *)bytes length:(int)length {
    
    if (self = [super init]) {
        
        _bn = BN_new();
        BN_bin2bn(bytes, length, _bn);
        
    }
    
    return self;
}


- (instancetype)initMPI:(const unsigned char *)mpi length:(int)length {
    
    if (self = [super init]) {
        
        _bn = BN_new();
        BN_mpi2bn(mpi, length, _bn);
        
    }
    
    return self;
}


+ (instancetype)zero {
    
    Bignum *bn = [[Bignum alloc] init];
    BN_zero(bn.bn);
    
    return bn;
}


+ (instancetype)one {
    
    Bignum *bn = [[Bignum alloc] init];
    BN_one(bn.bn);
    
    return bn;
}


- (void)setWord:(unsigned long)word {
    
    BN_set_word(_bn, word);
}


- (unsigned long)getWord {
    
    return BN_get_word(_bn);
}


- (void)rshift:(int)bits {
    
    BN_rshift(_bn, _bn, bits);
}


- (void)lshift:(int)bits {
    
    BN_lshift(_bn, _bn, bits);
}


- (Bignum *)rshifted:(int)bits {
    
    Bignum *result = [[Bignum alloc] init];
    BN_rshift(result.bn, _bn, bits);
    
    return result;
}


- (Bignum *)lshifted:(int)bits {
    
    Bignum *result = [[Bignum alloc] init];
    BN_lshift(result.bn, _bn, bits);
    
    return result;
}


- (instancetype)copy {
    
    Bignum *bn = [[Bignum alloc] init];
    BN_copy(bn.bn, _bn);
    
    return bn;
}


- (instancetype)add:(Bignum *)other {
    
    Bignum *result = [[Bignum alloc] init];
    BN_add(result.bn, _bn, other.bn);
    
    return result;
}


+ (int)sub:(Bignum *)lvalue rvalue:(Bignum *)rvalue result:(Bignum *)r {
    
    return BN_sub(r.bn, lvalue.bn, rvalue.bn);
}


+ (int)sum:(Bignum *)lvalue rvalue:(Bignum *)rvalue result:(Bignum *)r {
    
    return BN_add(r.bn, lvalue.bn, rvalue.bn);
}


+ (int)sum:(Bignum *)lvalue rvalue:(Bignum *)rvalue mod:(Bignum *)m result:(Bignum *)r {
    
    BN_CTX *ctx = BN_CTX_new();
    int result = BN_mod_add(r.bn, lvalue.bn, rvalue.bn, m.bn, ctx);
    
    BN_CTX_free(ctx);
    
    return result;
}


+ (int)mul:(Bignum *)lvalue rvalue:(Bignum *)rvalue result:(Bignum *)r {
    
    BN_CTX *ctx = BN_CTX_new();
    int result = BN_mul(r.bn, lvalue.bn, rvalue.bn, ctx);
    
    BN_CTX_free(ctx);
    
    return result;
}


+ (int)sub:(Bignum *)lvalue rvalue:(Bignum *)rvalue mod:(Bignum *)m result:(Bignum *)r {
    
    BN_CTX *ctx = BN_CTX_new();
    int result = BN_mod_sub(r.bn, lvalue.bn, rvalue.bn, m.bn, ctx);
    
    BN_CTX_free(ctx);
    
    return result;
}


+ (int)mul:(Bignum *)lvalue rvalue:(Bignum *)rvalue mod:(Bignum *)m result:(Bignum *)r {
    
    BN_CTX *ctx = BN_CTX_new();
    BN_mul(r.bn, lvalue.bn, rvalue.bn, ctx);
    int result = BN_div(NULL, r.bn, r.bn, m.bn, ctx);
    
    BN_CTX_free(ctx);
    
    return result;
}


+ (int)div:(Bignum *)divider reminder:(Bignum *)reminder lvalue:(Bignum *)lvalue rvalue:(Bignum *)rvalue {
    
    BN_CTX *ctx = BN_CTX_new();
    int result = BN_div(divider.bn, reminder.bn, lvalue.bn, rvalue.bn, ctx);
    
    BN_CTX_free(ctx);
    
    return result;
}


+ (int)mod:(Bignum *)value mod:(Bignum *)m {
    
    BN_CTX *ctx = BN_CTX_new();
    int result = BN_div(NULL, value.bn, value.bn, m.bn, ctx);
    
    BN_CTX_free(ctx);
    
    return result;
}


+ (int)modInverse:(Bignum *)value mod:(Bignum *)m result:(Bignum *)r {
    
    BN_CTX *ctx = BN_CTX_new();
    BN_mod_inverse(r.bn, value.bn, m.bn, ctx);
    
    BN_CTX_free(ctx);
    
    return 1;
}


- (int)isNegative {
    
    return BN_is_negative(_bn);
}


- (int)isZero {
    
    return BN_is_zero(_bn);
}


- (int)isOdd {
    
    return BN_is_odd(_bn);
}


- (int)compare:(Bignum *)other {
    
    return BN_cmp(_bn, other.bn);
}


- (int)numBits {
    
    return BN_num_bits(_bn);
}


- (int)numBytes {
    
    return BN_num_bytes(_bn);
}

- (void)makeBin:(unsigned char *)bin len:(int)len {
    
    int offset = len - [self numBytes];
    BN_bn2bin(_bn, bin + offset);
}


- (unsigned char *)mpi:(int *)size {
    
    int sz = BN_bn2mpi(_bn, nil);
    unsigned char *result = calloc(sz, sizeof(char));
    
    BN_bn2mpi(_bn, result);
    *size = sz;
    
    return result;
}


-(unsigned char *)bin {
    
    int offset = 32 - [self numBytes];
    unsigned char *bin = calloc(32, sizeof(char));
    
    BN_bn2bin(_bn, bin + offset);
    
    return bin;
}


-(void)dealloc {
    
    if (_bn != NULL) {
        
        BN_free(_bn);
        
    }
}


@end

