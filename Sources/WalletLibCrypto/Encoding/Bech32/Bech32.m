//
//  Bech32.m
//  WalletLibCrypto
//
//

#import "Bech32.h"
#import <Foundation/Foundation.h>


static const char *BECH_32_ALPHABET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";


@implementation Bech32


+ (NSString *)encode:(nonnull NSData *)data {
    
    return [self encode:data converted:NO];
}


+ (NSString *)encode:(nonnull NSData *)data converted:(BOOL)isConverted {
    
    NSData *converted;
    
    if (isConverted) {
        
        converted = data;
        
    } else {
        
        converted = [Bech32 convertBits:data from:8 to:5 strict:NO];
        
    }
    
    if (converted.length == 0) {
        
        return @"";
        
    }
    
    unsigned char output[converted.length + 1];
    memset(output, 0, sizeof(output));

    unsigned char *indexes = (unsigned char *)[converted bytes];
    
    for (int i = 0; i < converted.length; i++) {
        
        int index = indexes[i] & 0x1f;
        output[i] = (int)BECH_32_ALPHABET[index];
        
    }
    
    output[converted.length + 1] = '\0';
    
    NSMutableString *outstr = [NSMutableString stringWithCString:(const char *)output encoding:NSASCIIStringEncoding];
    
    return outstr;
}


+ (NSData *)decode:(nonnull NSString *)string {
    
    return [self decode:string convert:YES];
}


+ (NSData *)decode:(nonnull NSString *)string convert:(BOOL)convert {
    
    char *cstring = (char *)[string UTF8String];
    char bytes[string.length];
    memset(bytes, 0, string.length);
    
    int i = 0;
    
    for (char *p = cstring; p < cstring + string.length; p++) {
        
        const char *ch = strchr(BECH_32_ALPHABET, *p);
        int index = (int)(ch - BECH_32_ALPHABET);
        bytes[i] = index & 0xff;
        i++;
        
    }
    
    NSData *data = [NSData dataWithBytes:bytes length:string.length];
    
    if (convert) {
        
        return [Bech32 convertBits:data from:5 to:8 strict:true];
        
    } else {
        
        return data;
        
    }
}


+ (NSData *)convertBits:(NSData *)input from:(int)from to:(int)to strict:(BOOL)strict {
    
    float length = (float)(input.length * from) / (float)to;
    int outputLength = (strict) ? floorf(length) : ceil(length);
    
    unsigned char mask = (1 << to) - 1;
    
    unsigned char *ucharInput = (unsigned char *)[input bytes];
    unsigned char output[outputLength];
    memset(output, 0, sizeof(outputLength));
    
    int index = 0;
    int accumulator = 0;
    int bits = 0;
    
    for (int i = 0; i < input.length; i++) {
        
        int value = ucharInput[i];
        accumulator = (accumulator << from) | value;
        
        bits += from;
        
        while (bits >= to) {
            
            bits -= to;
            output[index] = (accumulator >> bits) & mask;
            index += 1;
            
        }
        
    }
    
    if (!strict) {
        
        if (bits > 0) {
            
            output[index] = accumulator << ((to - bits)) & mask;
            index += 1;
            
        }
        
    }
    
    return [NSData dataWithBytes:output length:outputLength];
}


@end
