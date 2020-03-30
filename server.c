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

#define SERV_KEY_PASS "server"
#define KEYFILE "./ssl/server.key"

int debug;
char *progname;

int main(int argc, char *argv[]) {
  
  int tap_fd;
  int flags = IFF_TUN;
  char if_name[IFNAMSIZ] = "";
  int header_len = IP_HDR_LEN;
  struct sockaddr_in client_tcp, client_udp;
  char remote_ip[16] = "";
  unsigned short int port = PORT;
  int dg_sock, net_fd, serv_sock, s_sock;
  socklen_t remotelen;
  char buffer[BUFSIZE];
  SSL_CTX *ctx;
  SSL *ssl;

  progname = argv[0];
  
  parse_args(argc, argv, "i:p:uahd", if_name, remote_ip, &port, &flags, &header_len, &tap_fd);

  //open a a stream socket for SSL, and a datagram socket for tunnel
  serv_sock = get_sock(port, SOCK_STREAM, 0);
  dg_sock = get_sock(port + 1, SOCK_DGRAM, IPPROTO_UDP);
  
  remotelen = sizeof(client_tcp);
  memset(&client_tcp, 0, remotelen);

  //wait for client via tcp
  if (listen(serv_sock, 5) < 0){
      perror("listen()");
      exit(1);
  }

  //create a new socket from the incoming connection
  //also loads remote info for conencted client
  if ((s_sock = accept(serv_sock, (struct sockaddr*)&client_tcp, &remotelen)) < 0){
      perror("accept()");
      exit(1);
  }
  do_debug("Received tcp connection\n");

  //establish SSL connection
  ctx = ssl_init_ctx(CA_FILE, KEYFILE, SERV_KEY_PASS);
  if (!ctx) {
    do_debug("SSL context init failed\n");
    ERR_print_errors_fp(stderr);
    abort();
  }
  do_debug("SSL context init complete\n");

  ssl = ssl_do_handshake(s_sock, ctx, 1);
  if (!ssl) {
    do_debug("SSL handshake failed\n");
    ERR_print_errors_fp(stderr);
    abort();
  }
  do_debug("SSL handshake complete\n");

  //generate key and send to client over SSL connection
  strcpy(key, "01234567890123456789012345678901");
  SSL_write(ssl, key, AES_KEYSIZE + 1);
  do_debug("Sent session key\n");

  //get client's datagram socket info
  if (recvfrom(dg_sock, buffer, BUFSIZE, 0, (struct sockaddr*)&client_udp, &remotelen) < 0) {
      perror("recvfrom()");
      exit(1);
  }
  do_debug("Connected via udp\n");

  do_tun_loop(tap_fd, dg_sock, client_udp);
  
  return(0);
}
