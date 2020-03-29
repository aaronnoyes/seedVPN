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

int debug;
char *progname;

int main(int argc, char *argv[]) {
  
  int tap_fd;
  int flags = IFF_TUN;
  char if_name[IFNAMSIZ] = "";
  int header_len = IP_HDR_LEN;
  struct sockaddr_in remote;
  char remote_ip[16] = "";
  unsigned short int port = PORT;
  int dg_sock, net_fd;
  socklen_t remotelen;
  char buffer[BUFSIZE];

  progname = argv[0];

  parse_args(argc, argv, "i:s:p:uahd", if_name, remote_ip, &port, &flags, &header_len, &tap_fd);

  dg_sock = get_sock(port, SOCK_DGRAM, IPPROTO_UDP);

  /* assign the destination address */
  memset(&remote, 0, sizeof(remote));
  remote.sin_family = AF_INET;
  remote.sin_addr.s_addr = inet_addr(remote_ip);
  remote.sin_port = htons(port);

  /* send buffer to server so that we can initialize */
  if (sendto(dg_sock, buffer, BUFSIZE, 0, (struct sockaddr*)&remote, sizeof(remote)) < 0) {
    perror("sendto()");
    exit(1);
  }

  do_debug("Client sent blank buffer to connect to server\n");
    
  do_tun_loop(tap_fd, dg_sock, remote);
  
  return(0);
}
