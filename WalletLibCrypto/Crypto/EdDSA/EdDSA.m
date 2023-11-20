//
//  EdDSA.m
//  WalletLibCrypto
//
//

#import <Foundation/Foundation.h>
#import <EdDSA.h>

#include "openssl/evp.h"
#include "ed25519.h"


@implementation EdDSA


+ (nonnull NSData *)sign:(NSData *)message key:(NSData *)key {
    
    EVP_PKEY *ed_key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL ,[key bytes], [key length]);
    
    size_t sig_len = 0;
    unsigned char sig[EVP_MAX_MD_SIZE];
    
    const unsigned char *msg = [message bytes];
    size_t msg_len = [message length];
    
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    
    EVP_DigestSignInit(md_ctx, NULL, EVP_sha256(), NULL, ed_key);

    /* Calculate the required size for the signature by passing a NULL buffer. */
    EVP_DigestSign(md_ctx, NULL, &sig_len, msg, msg_len);

    EVP_DigestSign(md_ctx, sig, &sig_len, msg, msg_len);

    EVP_MD_CTX_free(md_ctx);
        
    return [NSData dataWithBytes:sig length:sig_len];
    
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


@end
