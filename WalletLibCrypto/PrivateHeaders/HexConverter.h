//
//  HexConverter.h
//  WalletLibCrypto
//
//

#ifndef HexConverter_h
#define HexConverter_h


#import <Foundation/Foundation.h>


NS_ASSUME_NONNULL_BEGIN


@interface HexConverter : NSObject


+ (NSString *)convertToHexStringFromDecimalString:(NSString *)string;


+ (NSString *)convertToDecimalStringFromHexString:(NSString *)string;


@end


NS_ASSUME_NONNULL_END


#endif /* HexConverter_h */
