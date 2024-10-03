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


typedef NS_ENUM(NSUInteger, Base58EncodingType) {
    
    btc = 1,
    
    ripple = 2
    
};


+ (NSString *)encode:(nonnull NSData *)data;


+ (NSString *)encode:(nonnull NSData *)data type:(Base58EncodingType)type;


+ (NSData *)decode:(nonnull NSString *)string;


+ (NSData *)decode:(nonnull NSString *)string type:(Base58EncodingType)type;


+ (NSString *)encodeUsedChecksum:(nonnull NSData *)data;


+ (NSString *)encodeUsedChecksum:(nonnull NSData *)data type:(Base58EncodingType)type;


+ (NSData *)decodeUsedChecksum:(nonnull NSString *)string;


+ (NSData *)decodeUsedChecksum:(nonnull NSString *)string type:(Base58EncodingType)type;


@end


NS_ASSUME_NONNULL_END


#endif /* Base58_h */
