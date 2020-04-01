CC=gcc
CFLAGS=-g
INC=/usr/local/ssl/include/
LIB=/usr/local/ssl/lib/

all: server client common.o hmac.o aes.o ssl.o connections.o

server: server.c common.o aes.o hmac.o ssl.o connections.o
	$(CC) -I$(INC) -L$(LIB) -o server server.c common.o aes.o hmac.o ssl.o connections.o -lssl -lcrypto -ldl $(CFLAGS)

client: client.c common.o aes.o hmac.o ssl.o connections.o
	$(CC) -I$(INC) -L$(LIB) -o client client.c common.o aes.o hmac.o ssl.o connections.o -lssl -lcrypto -ldl $(CFLAGS)

common.o: common.c common.h
	$(CC) -I$(INC) -L$(LIB) -c common.c -lcrypto -ldl $(CFLAGS)

hmac.o: hmac.c hmac.h
	$(CC) -I$(INC) -L$(LIB) -c hmac.c -lcrypto -ldl $(CFLAGS)

aes.o: aes.c aes.h
	$(CC) -I$(INC) -L$(LIB) -c aes.c -lcrypto -ldl $(CFLAGS)

ssl.o: ssl.c ssl.h
	$(CC) -I$(INC) -L$(LIB) -c ssl.c -lssl -lcrypto -ldl $(CFLAGS)

connections.o: connections.c connections.h common.o
	$(CC) -I$(INC) -L$(LIB) -c connections.c common.o -lcrypto -ldl $(CFLAGS)

clean:
	rm -rf *.o server client
