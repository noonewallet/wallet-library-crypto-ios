//
//  Base58.h
//  WalletLibCrypto
//
//

#ifndef Base58_h
#define Base58_h


#import <Foundation/Foundation.h>


NS_ASSUME_NONNULL_BEGIN


@interface Base58 : NSObject


+ (NSString *)encode:(nonnull NSData *)data;


+ (NSData *)decode:(nonnull NSString *)string;


+ (NSString *)encodeUsedChecksum:(nonnull NSData *)data;


+ (NSData *)decodeUsedChecksum:(nonnull NSString *)string;


@end


NS_ASSUME_NONNULL_END


#endif /* Base58_h */
