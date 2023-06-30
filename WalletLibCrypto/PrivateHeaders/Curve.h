//
//  Curve.h
//  WalletLibCrypto
//
//

#ifndef Curve_h
#define Curve_h


#import <Foundation/Foundation.h>
#import "Bignum.h"


@class Curve;


NS_ASSUME_NONNULL_BEGIN


@interface CurvePoint : NSObject


- (instancetype)init:(Curve *)curve pointConversion:(int)conversion;


- (NSData *)data;


- (void)setPointWithData:(NSData *)data curve:(Curve *)curve;


- (void)mul:(Bignum *)factor curve:(Curve *)curve;


- (int)isAtInfinity:(Curve *)curve;


@end




@interface Curve : NSObject


- (instancetype)init;


- (instancetype)initBignum:(Bignum *)bignum;


- (instancetype)initX:(Bignum *)x yBit:(int)yBit;


- (int)degree;


- (Bignum *)order;


- (Bignum *)xPoint:(Bignum *)point;


- (Bignum *)yPoint:(Bignum *)point;


- (NSData *)newPointConversion:(int)conversion;


- (NSData *)newPoint:(NSData *)data conversion:(int)conversion;


- (NSData *)multiply:(CurvePoint *)point factor:(Bignum *)factor;


- (int)isAtInfinityPoint:(CurvePoint *)point;


- (void)getPublicKey:(const unsigned char*)key compressed:(int)compressed output:(unsigned char *_Nullable* _Nullable)output size:(int *)size;


- (int)ecdsaVerifySignature:(NSData *)signature forHash:(NSData *)hash;


- (void)recoveryPublicKeyU1:(Bignum *)u1 U2:(Bignum *)u2 compression:(int)compressionConversion data:(unsigned char *_Nullable* _Nullable)data size:(int *)size;


@end


NS_ASSUME_NONNULL_END


#endif /* Curve_h */
