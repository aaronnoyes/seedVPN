/**************************************************************************
 * simpletun.c                                                            *
 *                                                                        *
 * A simplistic, simple-minded, naive tunnelling program using tun/tap    *
 * interfaces and TCP. Handles (badly) IPv4 for tun, ARP and IPv4 for     *
 * tap. DO NOT USE THIS PROGRAM FOR SERIOUS PURPOSES.                     *
 *                                                                        *
 * You have been warned.                                                  *
 *                                                                        *
 * (C) 2009 Davide Brini.                                                 *
 *                                                                        *
 * DISCLAIMER AND WARNING: this is all work in progress. The code is      *
 * ugly, the algorithms are naive, error checking and input validation    *
 * are very basic, and of course there can be bugs. If that's not enough, *
 * the program has not been thoroughly tested, so it might even fail at   *
 * the few simple things it should be supposed to do right.               *
 * Needless to say, I take no responsibility whatsoever for what the      *
 * program might do. The program has been written mostly for learning     *
 * purposes, and can be used in the hope that is useful, but everything   *
 * is to be taken "as is" and without any kind of warranty, implicit or   *
 * explicit. See the file LICENSE for further details.                    *
 *************************************************************************/ 

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h> 
#include <sys/select.h>
#include <sys/time.h>
#include <errno.h>
#include <stdarg.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include "common.h"
#include "aes.h"
#include "hmac.h"
#include "ssl.h"
#include "connections.h"

#define CLI_KEY_PASS "client"
#define KEYFILE "./ssl/client.key"

int debug;
char *progname;

int main(int argc, char *argv[]) {
  
  int tap_fd;
  int flags = IFF_TUN;
  char if_name[IFNAMSIZ] = "";
  int header_len = IP_HDR_LEN;
  struct sockaddr_in server_tcp, server_udp;
  char server_ip[16] = "";
  unsigned short int port = PORT;
  int dg_sock, s_sock, net_fd;
  char buffer[BUFSIZE];
  SSL_CTX *ctx;
  SSL *ssl;

  progname = argv[0];

  parse_args(argc, argv, "i:s:p:uahd", if_name, server_ip, &port, &flags, &header_len, &tap_fd);

  s_sock = get_sock(NOPORT, SOCK_STREAM, 0);
  dg_sock = get_sock(NOPORT, SOCK_DGRAM, IPPROTO_UDP);

  //location of server's tcp port
  memset(&server_tcp, 0, sizeof(server_tcp));
  server_tcp.sin_family = AF_INET;
  server_tcp.sin_addr.s_addr = inet_addr(server_ip);
  server_tcp.sin_port = htons(port);

  //location of server's udp port
  memset(&server_udp, 0, sizeof(server_udp));
  server_udp.sin_family = AF_INET;
  server_udp.sin_addr.s_addr = inet_addr(server_ip);
  server_udp.sin_port = htons(port + 1);

  //establish tcp connection with server
  if (connect(s_sock, (struct sockaddr*) &server_tcp, sizeof(server_tcp)) < 0){
      perror("connect()");
      exit(1);
  }
  do_debug("Established tcp connection with server\n");

  //get SSL context
  ctx = ssl_init_ctx(CA_FILE , KEYFILE, CLI_KEY_PASS, 0);
  if (!ctx) {
    ERR_print_errors_fp(stderr);
    abort();
  }

  ssl = ssl_do_handshake(s_sock, ctx, 0);
  if (!ssl) {
    ERR_print_errors_fp(stderr);
    abort();
  }
  do_debug("SSL handshake complete\n");

  //get key from server
  SSL_read(ssl, key, AES_KEYSIZE + 1);
  do_debug("Received session key\n");

  //send buffer to server so that it gets our datagram socket
  if (sendto(dg_sock, buffer, BUFSIZE, 0, (struct sockaddr*)&server_udp, sizeof(server_udp)) < 0) {
    perror("sendto()");
    exit(1);
  }
  do_debug("Sent blank buffer to connect to server\n");
    
  do_tun_loop(tap_fd, dg_sock, server_udp);
  
  return(0);
}
