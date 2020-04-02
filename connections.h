#ifndef MCON_H
#define MCON_H

#define NOPORT -1
#define ANYPORT 0
#define IP_AD_LEN 16

//get_dg_sock(1)
// port - port to bind to, if NOPORT do not bind
int get_sock(int port, int type, int prot);

//tun_config(2)
// ip - the ip address to assign tun
// tap_fd = file descriptor for tun interface
int tun_config(char *ip, char *i_name);

//add_n_route()
void add_n_route(char *ip, char *dev);

#endif