//
//  HexConverter.m
//  WalletLibCrypto
//
//

#include <openssl/bn.h>
#import "HexConverter.h"


@implementation HexConverter


+ (NSString *)convertToHexStringFromDecimalString:(NSString *)string {
    
    const char *ascii = [string cStringUsingEncoding:NSASCIIStringEncoding];
    
    BIGNUM *bn = BN_new();
    BN_dec2bn(&bn, ascii);
    const char *hex = BN_bn2hex(bn);
    
    NSString *result = [NSString stringWithCString:hex encoding:NSASCIIStringEncoding];
    
    BN_free(bn);
    OPENSSL_free((void *)hex);
    
    return result;
}


+ (NSString *)convertToDecimalStringFromHexString:(NSString *)string {
    
    const char *ascii = [string cStringUsingEncoding:NSASCIIStringEncoding];
    
    BIGNUM *bn = BN_new();
    BN_hex2bn(&bn, ascii);
    const char *decimal = BN_bn2dec(bn);
    
    NSString *result = [NSString stringWithCString:decimal encoding:NSASCIIStringEncoding];
    
    BN_free(bn);
    OPENSSL_free((void *)decimal);
    
    return result;
}


@end
