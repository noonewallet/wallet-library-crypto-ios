//
//  Bignum.h
//  WalletLibCrypto
//
//

#ifndef Bignum_h
#define Bignum_h


#import <Foundation/Foundation.h>


NS_ASSUME_NONNULL_BEGIN


@interface Bignum : NSObject


- (instancetype)init:(Bignum *)bignum;


- (instancetype)initHex:(const char *)hex;


- (instancetype)init:(const unsigned char *)bytes length:(int)length;


- (instancetype)initMPI:(const unsigned char *)mpi length:(int)length;


+ (instancetype)zero;


+ (instancetype)one;


- (instancetype)copy;


- (void)setWord:(unsigned long)word;


- (unsigned long)getWord;


- (unsigned char *)bin;


- (unsigned char *)mpi:(int *)size;


- (instancetype)add:(Bignum *)other;


+ (int)sum:(Bignum *)lvalue rvalue:(Bignum *)rvalue result:(Bignum *)r;


+ (int)sub:(Bignum *)lvalue rvalue:(Bignum *)rvalue result:(Bignum *)r;


+ (int)mul:(Bignum *)lvalue rvalue:(Bignum *)rvalue result:(Bignum *)r;


+ (int)div:(Bignum *)divider reminder:(Bignum *)reminder lvalue:(Bignum *)lvalue rvalue:(Bignum *)rvalue;


+ (int)sum:(Bignum *)lvalue rvalue:(Bignum *)rvalue mod:(Bignum *)m result:(Bignum *)r;


+ (int)sub:(Bignum *)lvalue rvalue:(Bignum *)rvalue mod:(Bignum *)m result:(Bignum *)r;


+ (int)mul:(Bignum *)lvalue rvalue:(Bignum *)rvalue mod:(Bignum *)m result:(Bignum *)r;


+ (int)mod:(Bignum *)value mod:(Bignum *)m;


+ (int)modInverse:(Bignum *)value mod:(Bignum *)m result:(Bignum *)r;


- (void)rshift:(int)bits;


- (void)lshift:(int)bits;


- (Bignum *)rshifted:(int)bits;


- (Bignum *)lshifted:(int)bits;


- (int)isZero;


- (int)isNegative;


- (int)isOdd;


- (int)numBits;


- (int)numBytes;


- (int)compare:(Bignum *)other;


- (void)makeBin:(unsigned char *)bin len:(int)len;


@end


NS_ASSUME_NONNULL_END


#endif /* Bignum_h */
