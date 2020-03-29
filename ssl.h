#ifndef SSLV_H
#define SSLV_H

#include <openssl/ssl.h>

//relative path = BAD
#define CA_FILE "./ssl/ca.crt"

//ssl_init_ctx(3)
// cafile - the path to certificate authoritie's cert
// keyfile - the path to PEM encoded file with private key in it
// password - the password to decrypt the keyfile
SSL_CTX *ssl_init_ctx(char *cafile , char *keyfile, char *password);

//ssl_do_handshake(3)
// sock - tcp socket connected to peer
// ctx = SSL_CTX with parameters initialized
// server - if this is a server, listen
SSL *ssl_do_handshake(int sock, SSL_CTX *ctx, int server);

#endif