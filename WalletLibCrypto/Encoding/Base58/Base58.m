//
//  Base58.m
//  WalletLibCrypto
//
//

#import "Base58.h"
#import "Bignum.h"
#include "openssl/bn.h"

#include <CommonCrypto/CommonCrypto.h>


@implementation Base58


static const char *BASE_58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";


+ (NSString *)encodeUsedChecksum:(nonnull NSData *)data {
    
    NSMutableData *mdata = [NSMutableData dataWithData:data];
    
    int length = (int)mdata.length;
    
    unsigned char _hash[32];
    memset(_hash, 0, sizeof(_hash));
    unsigned char _hash2[32];
    memset(_hash2, 0, sizeof(_hash2));
    
    CC_SHA256([mdata bytes], length, _hash);
    CC_SHA256(_hash, 32, _hash2);
    
    NSData *checksum = [NSData dataWithBytes:_hash2 length:4];
    [mdata appendData:checksum];
    
    return [self encode:mdata];
}


+ (NSData *)decodeUsedChecksum:(nonnull NSString *)string {
    
    NSMutableData *output =  [NSMutableData dataWithData:[self decode:string]];
    
    if (output.length <= 4) {
        
        return [NSData data];
        
    }
    
    int length = (int)output.length - 4;
    
    NSMutableData *hash;
    
    unsigned char _hash[32];
    memset(_hash, 0, sizeof(_hash));
    
    unsigned char _hash2[32];
    memset(_hash2, 0, sizeof(_hash2));
    
    CC_SHA256([output bytes], length, _hash);
    CC_SHA256(_hash, 32, _hash2);
    
    hash = [NSMutableData dataWithBytes:_hash2 length:32];
    
    if (memcmp(hash.bytes, output.bytes + length, 4) != 0) {
        
        return nil;
        
    }
    
    [output setLength:length];
    
    return output;
}


+ (NSString *)encode:(nonnull NSData *)data {
    
    int dataLength = (int)[data length];
    int commonLength = dataLength + 5;

    unsigned char bytes[commonLength];
    unsigned char *input = (unsigned char *)[data bytes];
    
    memset(bytes, 0, commonLength);
    memcpy(bytes + 5, input, dataLength);
    
    int size = OSSwapHostToBigInt32(dataLength + 1);
    memcpy(bytes, &size, 4);
    
    Bignum *base58 = [[Bignum alloc] init]; [base58 setWord:58];
    Bignum *zero = [[Bignum alloc] init];
    Bignum *bn = [[Bignum alloc] initMPI:bytes length:commonLength];
    
    Bignum *divider = [[Bignum alloc] init];
    Bignum *reminder = [[Bignum alloc] init];
    
    int outputLength = ((dataLength * 138)/100) + 1;
    unsigned char output[outputLength];
    memset(output, 0, sizeof(output));
    
    int counter = 0;
    
    while ([bn compare:zero] > 0) {
        
        if ( ![Bignum div:divider reminder:reminder lvalue:bn rvalue:base58] ){
            
            return @"";
            
        }

        bn = [divider copy];
        unsigned long index = [reminder getWord];
        output[counter] = (int)BASE_58_ALPHABET[index];
        counter++;
        
    }
    
    for (unsigned char *p = input; p < (input + dataLength) && *p == 0; p++, ++counter) {
        
        output[counter] = (int)BASE_58_ALPHABET[0];
        
    }
    
    if (!reverse(output, outputLength, counter - 1)) {
        
        return @"";
        
    }
    
    output[counter] = '\0';
    
    NSString *result = [NSString stringWithCString:(const char*)output encoding:NSASCIIStringEncoding];
    
    return result;
}


+ (NSData *)decode:(nonnull NSString *)string {
    
    const char *cstring = [string cStringUsingEncoding:NSASCIIStringEncoding];
    
    Bignum *base58 = [[Bignum alloc] init]; [base58 setWord:58];
    Bignum *bnch = [[Bignum alloc] init];
    Bignum *bn = [[Bignum alloc] init];
    
    while (isspace(*cstring)) cstring++;
    
    int error = 0;
    
    for (const char *p = cstring; *p; p++) {
        
        const char *ch = strchr(BASE_58_ALPHABET, *p);
        
        if (ch == nil) {
            
            while (isspace(*p)) p++;
            error = *p != '\0';
            
            if (error) break;
            
        }
        
        [bnch setWord:(ch - BASE_58_ALPHABET)];
        
        error = ![Bignum mul:bn rvalue:base58 result:bn];
        if (error) break;
    
        error = ![Bignum sum:bn rvalue:bnch result:bn];
        if (error) break;
        
    }
    
    if (error) {
        
        return [NSData data];
        
    }
    
    int size = 0;
    int bytesSize = 0;
    
    unsigned char *bytes = [bn mpi:&size];
    bytesSize = size;
    
    error = size <= 4;
    
    if (error) {
        
        return [NSData data];
        
    }

    int zeros = 0;
    
    for (const char *p = cstring; *p == *BASE_58_ALPHABET; p++) {
        
        zeros++;
        
    }
    
    int offset = 0;
    
    if (bytes[4] == 0x00 && bytes[5] >= 0x80 ) {
        
        offset = 1;
        
    }
    
    size = size - 4;
    size = size - offset;
    
    unsigned char output[zeros + size];
    memset(output, 0, sizeof(output));
    memcpy(output + zeros, bytes + (4 + offset) , bytesSize - (4 + offset));

    NSData *data = [NSData dataWithBytes:output length:zeros + size];
    
    return data;
}


int reverse(unsigned char *bytes, int inputLength, int reverseLength) {
    
    if (inputLength < reverseLength) {
        
        return 0;
        
    }
    
    unsigned char byte;
    
    for (int i = 0, j = reverseLength; i < j; i++, j--) {
        
        byte = bytes[i];
        bytes[i] = bytes[j];
        bytes[j] = byte;
        
    }
    
    return 1;
}


@end


