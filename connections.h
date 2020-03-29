#ifndef MCON_H
#define MCON_H

#define NOPORT 0

//get_dg_sock(1)
// port - port to bind to, if NOPORT do not bind
int get_sock(int port, int type, int prot);

#endif