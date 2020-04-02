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
#include <sys/random.h>
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
#define CERTFILE "./ssl/server.crt"

int debug;
char *progname;

int main(int argc, char *argv[]) {
  
  int tap_fd;
  char if_name[IFNAMSIZ] = "tun0";
  struct sockaddr_in client_tcp, client_udp;
  char tun_ip[IP_AD_LEN] = "";
  char cli_vpn_ip[IP_AD_LEN] = "";
  unsigned short int port = PORT;
  int dg_sock, serv_sock, s_sock, tunsock;
  socklen_t remotelen;
  char buffer[BUFSIZE];
  unsigned char key[AES_KEYSIZE + 1];
  unsigned char iv[AES_IV_SIZE + 1];
  SSL_CTX *ctx;
  SSL *ssl;

  progname = argv[0];
  
  parse_args(argc, argv, "i:hdt:", NULL, tun_ip);

  //initialize tun interface
  if ( (tap_fd = tun_alloc(if_name, IFF_TUN | IFF_NO_PI)) < 0 ) {
    my_err("Error connecting to tun/tap interface %s!\n", if_name);
    exit(1);
  }
  do_debug("Successfully connected to interface %s\n", if_name);

  tunsock = tun_config(tun_ip, if_name);
  if (!tunsock) {
    exit(1);
  }

  //open a a stream socket for SSL, and a datagram socket for tunnel
  serv_sock = get_sock(port, SOCK_STREAM, 0);
  dg_sock = get_sock(NOPORT, SOCK_DGRAM, IPPROTO_UDP);
  
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
  ctx = ssl_init_ctx(CA_FILE, KEYFILE, SERV_KEY_PASS, CERTFILE, 1);
  if (!ctx) {
    do_debug("SSL context init failed\n");
    ERR_print_errors_fp(stderr);
    abort();
  }
  do_debug("SSL context init complete\n");

  ssl = ssl_handsh(s_sock, ctx, 1);
  if (!ssl) {
    do_debug("SSL handshake failed\n");
    ERR_print_errors_fp(stderr);
    abort();
  }
  do_debug("SSL handshake complete\n");

  //generate key and send to client over SSL connection
  getrandom(key, AES_KEYSIZE, 0);
  *(key+AES_KEYSIZE) = '\0';
  SSL_write(ssl, key, AES_KEYSIZE + 1);
  do_debug("Sent session key\n");

  //generate iv and send to client over SSL connection
  getrandom(iv, AES_KEYSIZE, 0);
  *(iv+AES_IV_SIZE) = '\0';
  SSL_write(ssl, iv, AES_IV_SIZE + 1);
  do_debug("Sent session key\n");

  //send VPN ip to server, get client's vpn IP
  SSL_write(ssl, tun_ip, IP_AD_LEN);
  SSL_read(ssl, cli_vpn_ip, IP_AD_LEN);
  add_n_route(cli_vpn_ip, if_name);
  do_debug("Added client's VPN IP to routing table\n");

  //location of client's udp port
  memset(&client_udp, 0, sizeof(client_udp));
  client_udp.sin_family = AF_INET;
  client_udp.sin_addr.s_addr = client_tcp.sin_addr.s_addr;
  client_udp.sin_port = htons(port + 1);

  //send buffer to client so that it gets our datagram socket
  if (sendto(dg_sock, buffer, BUFSIZE, 0, (struct sockaddr*)&client_udp, sizeof(client_udp)) < 0) {
    perror("sendto()");
    exit(1);
  }
  do_debug("Sent blank buffer to connect to client's UDP port\n");

  //test
  recvfrom(dg_sock, buffer, BUFSIZE, 0, (struct sockaddr*)&client_udp, &remotelen);
  do_debug("rec via udp\n");

  do_tun_loop(tap_fd, dg_sock, s_sock, ssl, client_udp, key, iv);

  close(dg_sock);
  close(s_sock);
  close(tunsock);
  close(serv_sock);
  close(tap_fd);
  
  return(0);
}
