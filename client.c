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
#define CERTFILE "./ssl/client.crt"

int debug;
char *progname;

int main(int argc, char *argv[]) {
  
  int tap_fd;
  char if_name[IFNAMSIZ] = "tun0";
  struct sockaddr_in server_tcp, server_udp;
  char server_ip[IP_AD_LEN] = "";
  char tun_ip[IP_AD_LEN] = "";
  char serv_vpn_ip[IP_AD_LEN] = "";
  unsigned short int port = PORT;
  int dg_sock, s_sock, tunsock;
  char buffer[BUFSIZE];
  unsigned char key[AES_KEYSIZE + 1];
  unsigned char iv[AES_IV_SIZE + 1];
  SSL_CTX *ctx;
  SSL *ssl;

  progname = argv[0];

  parse_args(argc, argv, "i:s:hdt:", server_ip, tun_ip);

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

  s_sock = get_sock(NOPORT, SOCK_STREAM, 0);
  dg_sock = get_sock(port + 1, SOCK_DGRAM, IPPROTO_UDP);

  //location of server's tcp port
  memset(&server_tcp, 0, sizeof(server_tcp));
  server_tcp.sin_family = AF_INET;
  server_tcp.sin_addr.s_addr = inet_addr(server_ip);
  server_tcp.sin_port = htons(port);

  //establish tcp connection with server
  if (connect(s_sock, (struct sockaddr*) &server_tcp, sizeof(server_tcp)) < 0){
      perror("connect()");
      exit(1);
  }
  do_debug("Established tcp connection with server\n");

  //get SSL context
  ctx = ssl_init_ctx(CA_FILE , KEYFILE, CLI_KEY_PASS, CERTFILE, 0);
  if (!ctx) {
    ERR_print_errors_fp(stderr);
    abort();
  }

  //do SSL handshake with the server
  ssl = ssl_handsh(s_sock, ctx, 0);
  if (!ssl) {
    do_debug("SSL handshake failed\n");
    ERR_print_errors_fp(stderr);
    abort();
  }
  do_debug("SSL handshake complete\n");

  //get key from server
  SSL_read(ssl, key, AES_KEYSIZE + 1);
  do_debug("Received session key\n");

  //get iv from server
  SSL_read(ssl, iv, AES_IV_SIZE + 1);
  do_debug("Received IV\n");

  //read server VPN ip, get send cli vpn IP
  SSL_read(ssl, serv_vpn_ip, IP_AD_LEN);
  SSL_write(ssl, tun_ip, IP_AD_LEN);
  add_n_route(serv_vpn_ip, if_name);
  do_debug("Added server's VPN IP to routing table\n");

  //get server's datagram socket info
  if (recvfrom(dg_sock, buffer, BUFSIZE, 0, (struct sockaddr*)&client_udp, &remotelen) < 0) {
      perror("recvfrom()");
      exit(1);
  }
  do_debug("Connected to server via udp\n");
    
  do_tun_loop(tap_fd, dg_sock, s_sock, ssl, server_udp, key, iv);

  close(dg_sock);
  close(s_sock);
  close(tunsock);
  close(tap_fd);
  
  return(0);
}
