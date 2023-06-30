//
//  Bech32.h
//  WalletLibCrypto
//
//

#ifndef Bech32_h
#define Bech32_h


#import <Foundation/Foundation.h>


NS_ASSUME_NONNULL_BEGIN


@interface Bech32 : NSObject


+ (NSString *)encode:(nonnull NSData *)data;


+ (NSString *)encode:(nonnull NSData *)data converted:(BOOL)isConverted;


+ (NSData *)decode:(nonnull NSString *)string;


+ (NSData *)decode:(nonnull NSString *)string convert:(BOOL)convert;


+ (NSData *)convertBits:(NSData *)input from:(int)from to:(int)to strict:(BOOL)strict;


@end

NS_ASSUME_NONNULL_END


#endif /* Bech32_h */
