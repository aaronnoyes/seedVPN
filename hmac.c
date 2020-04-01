#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

#include "hmac.h"

//set up digest context
//this code is common to sign and verify
//does not need to be callable outside of this library
//returns md context already set up with private key
EVP_MD_CTX *setup_digest(char *key) {
    EVP_MD_CTX* ctx = NULL;
    EVP_PKEY* pkey = NULL;

    //get sha256 digest
    const EVP_MD* md = EVP_sha256();
    if (!md) {
        ERR_print_errors_fp(stderr);
        abort();
    }

    //init digest context
    ctx = EVP_MD_CTX_create();
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        abort();
    }


    //set private key
    pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, key, strlen(key));
    if (!pkey) {
        ERR_print_errors_fp(stderr);
        abort();
    }

    //initialize context
    if(!(EVP_DigestSignInit(ctx, NULL, md, NULL, pkey))) {
        ERR_print_errors_fp(stderr);
        abort();
    }

    return ctx;
}

int sign_hmac(char *msg, int msg_len, char *hmac, char *key) {
    EVP_MD_CTX *ctx = setup_digest(key);
    int hmac_len;

    //hash message
    if(!(EVP_DigestSignUpdate(ctx, msg, msg_len))) {
        return 0;
    }

    //store messgae in hmac
    if(!(EVP_DigestSignFinal(ctx, hmac, (size_t*)&hmac_len))) {
        return 0;
    }
    
    //hashing was successful, return length of hmac which is stored in hmac
    return hmac_len;
}

int verify_hmac(char *msg, int msg_len, char *hmac, char *key) {
    char ver_hmac[HMAC_SIZE];

    //sign the provided message and store it in ver_hmac
    //if that fails, fail
    int ver_hmac_len = sign_hmac(msg, msg_len, ver_hmac, key);
    if (!ver_hmac_len) {
        return 0;
    }

    //compare the supplied and computer hmacs
    if (memcmp(ver_hmac, hmac, HMAC_SIZE)) {
        return 0;
    }
    
    //nothing fails, return true
    return 1;

}