#include <openssl/ssl.h>
#include "ssl.h"

//password retrieved to decrypt keyfile
static char *keyfile_pass;

//callback to get password to decrypt keyfile
//should not be callable outside the library
static int get_keyfile_pass(char *buf, int num, int rwflag, void *userdata) {
    //get length of password
    int pass_len = strlen(keyfile_pass);
    if (num < pass_len +1) {
        return(0);
    }

    strcpy(buf, keyfile_pass);
    return(pass_len);
}

SSL_CTX *ssl_init_ctx(char *cafile , char *keyfile, char *password) {
    SSL_CTX *ctx;
    SSL_METHOD *method;


    //set up context using SSL/TLS
    //openSSL will negitiate the best to use
    method = SSLv23_client_method();
    ctx = SSL_CTX_new(method);

    //load the CA's cert
    if (!SSL_CTX_load_verify_locations(ctx, CA_FILE, NULL)) {
        return NULL;
    }

    //get the password to decrypt keyfile using get_keyfile_pass()
    keyfile_pass = password;
    SSL_CTX_set_default_passwd_cb(ctx, get_keyfile_pass);

    //load private key into context
    //private keys are in PEM format
    if(!(SSL_CTX_use_PrivateKey_file(ctx, keyfile, SSL_FILETYPE_PEM))) {
        return NULL;
    }

    return ctx;
}

SSL *ssl_do_handshake(int sock, SSL_CTX *ctx, int server) {
    BIO *bio;
    SSL *ssl;
    int conn_status;

    //get ssl struct from context and bind BIO to the socket
    ssl = SSL_new(ctx);
    bio = BIO_new_socket(sock, BIO_NOCLOSE);

    //ssl should read and write via the BIO
    SSL_set_bio(ssl, bio, bio);

    //client and server should both check eachother's certificates
    SSL_set_verify(ssl, SSL_VERIFY_PEER, NULL);

    //server wait for connection
    //client try to connect
    if (server) {
        conn_status = SSL_accept(ssl);
    }
    else {
        conn_status = SSL_connect(ssl);
    }

    //if connection fails, return NULL
    if (!conn_status) {
        return NULL;
    }

    return ssl;
}
