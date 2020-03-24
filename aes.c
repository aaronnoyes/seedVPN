#include <openssl/evp.h>

#include "aes.h"

int encrypt_aes(char *plain, int plain_len, char *cipher, char *key, char *iv) {
    EVP_CIPHER_CTX *ctx;    
    int len;
    int ciphertext_len;

    //initialize cipher context
    if(!(ctx = EVP_CIPHER_CTX_new())) {
      return 0;
    }

    //use aes-256 in CBC mode for encyption
    if(EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        return 0;
    }

    //encrypt plaintext
    if(1 != EVP_EncryptUpdate(ctx, cipher, &len, plain, plain_len)) {
        return 0;
    }
    ciphertext_len = len;

    if(1 != EVP_EncryptFinal_ex(ctx, cipher + len, &len)) {
        return 0;
    }
    ciphertext_len += len;

    //free cipher context
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int decrypt_aes(char *cipher, int cipher_len, char *plain, char *key, char *iv) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    //initialize cipher context
    if(!(ctx = EVP_CIPHER_CTX_new())) {
      return 0;
    }

    // use aes-256 in CBC mode for decryption
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1 ) {
        return 0;
    }

    //decrypt ciphertext from buffer
    if (EVP_DecryptUpdate(ctx, plain, &len, cipher, cipher_len) != 1) {
        return 0;
    }
    plaintext_len = len;

    if (EVP_DecryptFinal_ex(ctx, plain + len, &len) != 1) {
        return 0;
    }
    plaintext_len += len;

    //free cipher context
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}