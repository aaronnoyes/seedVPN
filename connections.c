#include <sys/socket.h>
#include <arpa/inet.h>
#include "connections.h"

int get_dg_sock(int port) {
    int sock_fd, optval = 1;
    struct sockaddr_in local;

    if ( (sock_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
        perror("socket()");
        exit(1);
    }

    //server should bind to a local port
    if (port) {
        /* avoid EADDRINUSE error on bind() */
        if(setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&optval, sizeof(optval)) < 0){
            perror("setsockopt()");
            exit(1);
        }
        
        memset(&local, 0, sizeof(local));
        local.sin_family = AF_INET;
        local.sin_addr.s_addr = htonl(INADDR_ANY);
        local.sin_port = htons(port);
        if (bind(sock_fd, (struct sockaddr*) &local, sizeof(local)) < 0){
            perror("bind()");
            exit(1);
        }
    }

    return sock_fd;

}