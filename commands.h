#ifndef SSL_COM_H
# define SSL_COM_H

#include "openssl/ssl.h"

#define CMD_LEN 128
#define CMD_T_LEN 16
#define CONF_LEN 5

int parse_command(char *command, char *key, char *iv, char *hmac_key,int sender, SSL *ssl);

#endif