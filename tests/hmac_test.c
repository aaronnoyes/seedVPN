#include "../hmac.h"

int main() {
    char *key = "123456";
    char *message = "Hello, World!";
    char hmac[HMAC_SIZE];
    int hmac_len;

    hmac_len = sign_hmac(message, strlen(message), hmac, key);
    if (!hmac_len) {
        printf("Failed to sign message\n");
        exit(1);
    }

    if (!verify_hmac(message, strlen(message), hmac, key)) {
        printf("Failed to verify message\n");
        exit(1);
    }
    
    printf("HMAC verified!\n");
    return 0;
}