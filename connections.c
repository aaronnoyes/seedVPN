#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <sys/types.h>
#include <errno.h>

#include "connections.h"

int get_sock(int port, int type, int prot) {
    int sock_fd, optval = 1;
    struct sockaddr_in local;

    if ( (sock_fd = socket(AF_INET, type, prot)) < 0) {
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

int tun_config(char *ip, char *i_name) {
  struct ifreq ifr;
  struct sockaddr_in tun;
  char *netmask = "255.255.255.0"; //netmask will always be the same for this implementation
  int r, sock;

  //get socket for ioctl
  sock = get_sock(0, SOCK_DGRAM, 0);
  if (!sock) {
    do_debug("Failed to create socket for tun\n");
    return sock;
  }

  //clear memory for address and req
  memset(&tun, 0, sizeof(tun));
  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, i_name, IFNAMSIZ);

  //set address
  tun.sin_family = AF_INET;
  r = inet_pton(tun.sin_family, ip, &tun.sin_addr);
  if (r == 0) {
    do_debug("invalid ip\n");
  }
  if (r == -1) {
    do_debug("invalid family\n");
  }
  memcpy(&ifr.ifr_addr, &tun, sizeof(struct sockaddr));
  r = ioctl(sock, SIOCSIFADDR, &ifr);
  if (r < 0) {
    do_debug("Failed to set interface address errno: %d\n", errno);
    return 0;
  }

  //set netmask
  tun.sin_family = AF_INET;
  r = inet_pton(tun.sin_family, netmask, &tun.sin_addr);
  if (r == 0) {
    do_debug("invalid ip\n");
  }
  if (r == -1) {
    do_debug("invalid family\n");
  }
  memcpy(&ifr.ifr_addr, &tun, sizeof(struct sockaddr));
  r = ioctl(sock, SIOCSIFNETMASK, &ifr);
  if (r < 0) {
    do_debug("Failed to set interface netmask errno: %d\n", errno);
    return 0;
  }

  //reset request
  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, i_name, IFNAMSIZ);

  //set interface up
  ifr.ifr_flags |= IFF_UP;
  r = ioctl(sock, SIOCSIFFLAGS, &ifr);
  if (r < 0) {
    do_debug("Failed to set interface up errno: %d\n", errno);
    return 0;
  }

  return sock;
}

void add_n_route(char *ip, char *dev) {
    //args are all static so as not to be abused
    char *rt_path = "/usr/sbin/route";
    char *args[] = {"route", "add", "-net", "", "netmask", "255.255.255.0", "dev", "", NULL};
    args[3] = ip;
    args[7] = dev;
    int r, pid;

    //fork to call the program
    //use execv instead of system because system spawns a shell
    pid = fork();
    if (pid == 0) {
        r = execv(rt_path, args);
        if (r < 0) {
            perror("Failed to add route\n");
            exit(1);
        }
    }
    else {
        wait(&pid);
    }
}