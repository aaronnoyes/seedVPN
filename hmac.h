#include <openssl/evp.h>

//sha256 outputs 64 bytes
#define HMAC_SIZE 64

//sign_hmac(4)
// msg - message to be hashed
// msg_len - length of message to by ecrypted
// hmac - pointer to where the hmac is stored
// key - the private key used to sign the hmac
// returns length of hashed message or 0 on failure
int sign_hmac(char *msg, int msg_len, char *hmac, char *key);

//verify_hmac(4)
// msg - original message
// msg_len - length of message
// hmac - received hash of message
// key - the private key used to sign the hmac
// returns 1 if the same hmac is calculated, 0 if it is not the same
int verify_hmac(char *msg, int msg_len, char *hmac, char *key);