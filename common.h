#ifndef COMMON_H
#define COMMON_H

/* buffer for reading from tun/tap interface, must be >= 1500 */
#define BUFSIZE 2000   
#define CLIENT 0
#define SERVER 1
#define PORT 55555

/* some common lengths */
#define IP_HDR_LEN 20
#define ETH_HDR_LEN 14
#define ARP_PKT_LEN 28

/**************************************************************************
 * usage: prints usage and exits.                                         *
 **************************************************************************/
void usage(char *progname);

/**************************************************************************
 * tun_alloc: allocates or reconnects to a tun/tap device. The caller     *
 *            needs to reserve enough space in *dev.                      *
 **************************************************************************/
int tun_alloc(char *dev, int flags);

/**************************************************************************
 * cread: read routine that checks for errors and exits if an error is    *
 *        returned.                                                       *
 **************************************************************************/
int cread(int fd, char *buf, int n);

/**************************************************************************
 * cwrite: write routine that checks for errors and exits if an error is  *
 *         returned.                                                      *
 **************************************************************************/
int cwrite(int fd, char *buf, int n);

/**************************************************************************
 * read_n: ensures we read exactly n bytes, and puts those into "buf".    *
 *         (unless EOF, of course)                                        *
 **************************************************************************/
int read_n(int fd, char *buf, int n);

/**************************************************************************
 * do_debug: prints debugging stuff (doh!)                                *
 **************************************************************************/
void do_debug(char *msg, ...);

/**************************************************************************
 * my_err: prints custom error messages on stderr.                        *
 **************************************************************************/
void my_err(char *msg, ...);

//tap2net
// tap_fd - file descriptor for tap interface
// sock_fd - file descriptor for socket to write to
// remote - socket of remote
void tap2net(int tap_fd, int sock_fd, struct sockaddr_in remote);

//net2tap
// tap_fd - file descriptor for tap interface
// sock_fd - file descriptor for socket to write to
// remote - socket of remote
void net2tap(int net_fd, int sock_fd, int tap_fd, struct sockaddr_in remote);

//parse command line arguments and perform setup
void parse_args(int argc, char *argv[], char *optstr, char *if_name, char *remote_ip, unsigned short int *port, int *flags, int *header_len, int *tap_fd);

#endif