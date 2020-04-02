#include <string.h>
#include "commands.h"
#include "openssl/ssl.h"
#include "aes.h"


int parse_command(char *command, char *key, char *iv, int sender, SSL *ssl) {
    char *buf;
    char *cmd_type[CMD_T_LEN];
    char *arg[CMD_LEN - CMD_T_LEN];
    char *val_to_change;
    int corr_len;
    char *conf = "conf";

    //get command
    buf = strtok(command, " ");
    strncpy(cmd_type, buf, CMD_T_LEN);

    //get argument
    buf = strtok(NULL, " "); 
    strncpy(arg, buf, CMD_T_LEN);

    //parse command, check correct length
    if (!strcmp(cmd_type, "key")) {
        if(strlen(arg) != AES_KEYSIZE) {
            val_to_change = key;
            corr_len = AES_KEYSIZE;
        }
        else {
            return 0;
        }
    }
    else if (!strcmp(cmd_type, "key")) {
        if(strlen(arg) != AES_IV_SIZE) {
            val_to_change = iv;
            corr_len = AES_IV_SIZE;
        }
        else {
            return 0;
        }
    }
    else {
        return 0;
    }

    //clear previous value to be safe
    memset(val_to_change, 0, corr_len);

    //copy arument
    strncpy(val_to_change, arg, CMD_LEN);

    //if we sent the command, wait for the peer to respond
    //this keeps encryption in sync (hopefully)
    if (sender) {
        SSL_read(ssl, conf, CONF_LEN);
    }
    else {
        SSL_write(ssl, conf, CONF_LEN);
    }

    return 1;

}