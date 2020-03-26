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

/* buffer for reading from tun/tap interface, must be >= 1500 */
#define BUFSIZE 2000   
#define CLIENT 0
#define SERVER 1
#define PORT 55555

/* some common lengths */
#define IP_HDR_LEN 20
#define ETH_HDR_LEN 14
#define ARP_PKT_LEN 28

int debug;
char *progname;

/* dummy key and IV, MUST BE REMOVED */
unsigned char *key = (unsigned char *)"01234567890123456789012345678901";
unsigned char *iv = (unsigned char *)"0123456789012345";

int tun_alloc(char *dev, int flags) {

  struct ifreq ifr;
  int fd, err;

  if( (fd = open("/dev/net/tun", O_RDWR)) < 0 ) {
    perror("Opening /dev/net/tun");
    return fd;
  }

  memset(&ifr, 0, sizeof(ifr));

  ifr.ifr_flags = flags;

  if (*dev) {
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
  }

  if( (err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0 ) {
    perror("ioctl(TUNSETIFF)");
    close(fd);
    return err;
  }

  strcpy(dev, ifr.ifr_name);

  return fd;
}

int cread(int fd, char *buf, int n){
  
  int nread;

  if((nread=read(fd, buf, n))<0){
    perror("Reading data");
    exit(1);
  }
  return nread;
}

int cwrite(int fd, char *buf, int n){
  
  int nwrite;

  if((nwrite=write(fd, buf, n))<0){
    perror("Writing data");
    exit(1);
  }
  return nwrite;
}

int read_n(int fd, char *buf, int n) {

  int nread, left = n;

  while(left > 0) {
    if ((nread = cread(fd, buf, left))==0){
      return 0 ;      
    }else {
      left -= nread;
      buf += nread;
    }
  }
  return n;  
}

void do_debug(char *msg, ...){
  
  va_list argp;
  
  if(debug){
	va_start(argp, msg);
	vfprintf(stderr, msg, argp);
	va_end(argp);
  }
}

void my_err(char *msg, ...) {

  va_list argp;
  
  va_start(argp, msg);
  vfprintf(stderr, msg, argp);
  va_end(argp);
}

void tap2net(int tap_fd, int sock_fd, struct sockaddr_in remote) {
    /* data from tun/tap: read it, ecrypt it, and write it to the network */
    static unsigned long int n_tap2net = 0;
    char buffer[BUFSIZE];
    unsigned char cipher[BUFSIZE];
    char hmac[HMAC_SIZE];
    int cipher_len, hmac_len;
    uint16_t nread, nwrite, plength;

    /*read plaintext from the tunnel */
    nread = cread(tap_fd, buffer, BUFSIZE);

    n_tap2net++;
    do_debug("TAP2NET %lu: Read %d bytes from the tap interface\n", n_tap2net, nread);

    //sign HMAC of message
    hmac_len = sign_hmac(buffer, nread, hmac, key);
    if (!hmac_len) {
        ERR_print_errors_fp(stderr);
        abort();
    }
    do_debug("TAP2NET %lu: signed hmac\n", n_tap2net);

    //encrypt plaintext
    cipher_len = encrypt_aes(buffer, nread, cipher, key, iv);
    if (!cipher_len) {
        ERR_print_errors_fp(stderr);
        abort();
    }
    do_debug("TAP2NET %lu: encrypted %d cipher bytes\n", n_tap2net, cipher_len);

    //copy hmac then cipher to buffer
    memcpy(buffer, hmac, HMAC_SIZE);
    memcpy(buffer + HMAC_SIZE, cipher, cipher_len);

    /* send ecnrypted packet packet over the network */
    if ((nwrite = sendto(sock_fd, buffer, cipher_len + HMAC_SIZE, 0, (struct sockaddr*)&remote, sizeof(remote))) < 0) {
        perror("sendto()");
        exit(1);
    }

    do_debug("TAP2NET %lu: Written %d bytes to the network\n", n_tap2net, nwrite);

}

void net2tap(int net_fd, int sock_fd, int tap_fd, struct sockaddr_in remote) {
    /* data from the network: read it, decrypt it, and write it to the tun/tap interface. */
    uint16_t nread, nwrite, plength;
    unsigned char plain[BUFSIZE];
    int plain_len;
    char rec_hmac[HMAC_SIZE];
    static unsigned long int n_net2tap = 0;
    char buffer[BUFSIZE];

    n_net2tap++;

    /* read packet */
    socklen_t remotelen = sizeof(remote);
    memset(&remote, 0, remotelen);
    if ((nread = recvfrom(sock_fd, buffer, BUFSIZE, 0, (struct sockaddr*)&remote, &remotelen)) < 0) {
        perror("recvfrom()");
        exit(1);
    }
    do_debug("NET2TAP %lu: Read %d bytes from the network\n", n_net2tap, nread);

    // if(nread == 0) {
    //     /* ctrl-c at the other end */
    //     break;
    // }

    //read the received hmac
    memcpy(rec_hmac, buffer, HMAC_SIZE);

    //decrypt incoming network traffic
    plain_len = decrypt_aes(buffer + HMAC_SIZE, nread - HMAC_SIZE, plain, key, iv);
    if (!plain_len) {
        ERR_print_errors_fp(stderr);
        abort();
    }
    do_debug("NET2TAP %lu: decrypted %d bytes from cipher\n", n_net2tap, plain_len);

    //if the hmac matches the plaintext, move it along
    if (verify_hmac(plain, plain_len, rec_hmac, key)) {
        do_debug("NET2TAP %lu: verified HMAC\n", n_net2tap);
        /* plaintext contains decrypted packet, write it into the tun/tap interface */ 
        nwrite = cwrite(tap_fd, plain, plain_len);
        do_debug("NET2TAP %lu: Written %d bytes to the tap interface\n", n_net2tap, nwrite);
    }
    else {
        do_debug("NET2TAP %lu: refused HMAC\n", n_net2tap);
    }
}