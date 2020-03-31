#ifndef AES_H
#define AES_H

#include <openssl/evp.h>

//aes-256 keys are 256 bits or 32 bytes
#define AES_KEYSIZE 32
#define AES_IV_SIZE 16

//encrypt_aes(4)
// plain - message to be ecnrypted
// plain_len - length of message to by ecrypted
// cipher - pointer to where the hmac is stored
// key - the private key used to encrypt
// iv - iv for encryption
// returns length of cipher or 0 on failure
int encrypt_aes(char *plain, int plain_len, char *cipher, char *key, char *iv);

//decrypt_aes(4)
// cipher - encrypted message
// cipher_len - length of message to by ciphertext
// plain - pointer to where the decrypted message is stored
// key - the private key used to decrypt
// iv - iv for decryption
// returns length of cipher or 0 on failure
int decrypt_aes(char *cipher, int cipher_len, char *plain, char *key, char *iv);

#endif