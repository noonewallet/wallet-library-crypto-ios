//
//  EdDSA.m
//  WalletLibCrypto
//
//

#import <Foundation/Foundation.h>
#import <EdDSA.h>

#include "openssl/evp.h"
#include "ed25519.h"
#include "TweetNacl.h"


@implementation EdDSA


+ (nonnull NSData *)sign:(NSData *)message key:(NSData *)key {
    
    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL ,[key bytes], [key length]);
    
    size_t sig_len = 0;
    unsigned char sig[EVP_MAX_MD_SIZE];
    
    const unsigned char *msg = [message bytes];
    size_t msg_len = [message length];
    
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    
    int err = 0;
    
    if (!EVP_DigestSignInit(md_ctx, NULL, NULL, NULL, pkey) ||
        !EVP_DigestSign(md_ctx, NULL, &sig_len, msg, msg_len) ||
        !EVP_DigestSign(md_ctx, sig, &sig_len, msg, msg_len)) {
        
        err = 1;
        
    }

    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);
    
    if (err) {
        
        return [NSData data];
        
    } else {
        
        return [NSData dataWithBytes:sig length:sig_len];
        
    }
         
}


+ (nonnull NSData *)sign:(NSData *)message donnaKey:(NSData *)key {

    size_t msgLen = [message length];
    const unsigned char *skey = (unsigned char *)[key bytes];
    const unsigned char *msg = (unsigned char *)[message bytes];

    ed25519_signature sig;
    ed25519_public_key pkey;

    cardano_crypto_ed25519_publickey(skey, pkey);
    cardano_crypto_ed25519_sign(msg, msgLen, NULL, 0, skey, pkey, sig);

    static const size_t sigLen = 64;

    NSData *result = [NSData dataWithBytes:sig length:sigLen];

    return result;
}


+ (nonnull NSData *)sign:(NSData *)message tweetnacl:(NSData *)key {

    const unsigned char *skey = (unsigned char *)[key bytes];
    const unsigned char *msg = (unsigned char *)[message bytes];
    unsigned long long msgLength = [message length];

    unsigned long long sigLength = 64;
    unsigned char sig[sigLength];
    
    crypto_sign_ed25519_tweet(sig, &sigLength, msg, msgLength, skey);

    NSData *result = [NSData dataWithBytes:sig length:sigLength];

    return result;
}


+ (BOOL)validateSignature:(NSData *)signature message:(NSData *)message forPublicKey:(NSData *)key {

    const unsigned char *sig = (unsigned char *)[signature bytes];
    size_t sig_len = [signature length];
    
    const unsigned char *msg = (unsigned char *)[message bytes];
    size_t msg_len = [message length];
    
    const unsigned char *pubkey = (unsigned char *)[key bytes];
    size_t pubkey_len = [key length];
    
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    
    EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, pubkey, pubkey_len);
    
    int err = 0;
    
    if (!EVP_DigestVerifyInit(md_ctx, NULL, NULL, NULL, pkey) ||
        !EVP_DigestVerify(md_ctx, sig, sig_len, msg, msg_len)) {
        
        err = 1;
        
    }
    
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);

    if (err == 1) {

        return NO;

    } else {

        return YES;
        
    }
    
}

+ (BOOL)validateDonnaSignature:(NSData *)signature message:(NSData *)message forPublicKey:(NSData *)key {

    static const size_t sigLen = 64;
    static const size_t keyLen = 32;

    if (([signature length] != sigLen) ||
        ([key length] != keyLen) ||
        ([message length] == 0)) {

        return NO;

    }

    const unsigned char *vkey = (unsigned char *)[key bytes];
    const unsigned char *msg = (unsigned char *)[message bytes];
    const unsigned char *sig = (unsigned char *)[signature bytes];

    int result = cardano_crypto_ed25519_sign_open(msg, [message length], vkey, sig);

    if (result == 0) {

        return YES;

    } else {

        return NO;

    }
}


+ (BOOL)validateTweetNaclSignature:(NSData *)signature message:(NSData *)message forPublicKey:(NSData *)key {

    static const unsigned long long sigLen = 96;
    static const size_t keyLen = 32;

    if (([signature length] != sigLen) ||
        ([key length] != keyLen) ||
        ([message length] == 0)) {

        return NO;

    }
    
    unsigned char *msg = (unsigned char *)[message bytes];
    unsigned long long msgLenght = [message length];
    const unsigned char *sig = (unsigned char *)[signature bytes];
    const unsigned char *vkey = (unsigned char *)[key bytes];

    int result = crypto_sign_ed25519_tweet_open(msg, &msgLenght, sig, sigLen, vkey);

    if (result == 0) {

        return YES;

    } else {

        return NO;

    }
}


@end
