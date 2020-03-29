CC=gcc
CFLAGS=
INC=/usr/local/ssl/include/
LIB=/usr/local/ssl/lib/

all: server client common.o hmac.o aes.o ssl.o

server: server.c common.o aes.o hmac.o ssl.o
	$(CC) -I$(INC) -L$(LIB) -o server server.c common.o aes.o hmac.o ssl.o -lcrypto -ldl

client: client.c common.o aes.o hmac.o
	$(CC) -I$(INC) -L$(LIB) -o client client.c common.o aes.o hmac.o -lcrypto -ldl

common.o: common.c common.h
	$(CC) -I$(INC) -L$(LIB) -c common.c -lcrypto -ldl

hmac.o: hmac.c hmac.h
	$(CC) -I$(INC) -L$(LIB) -c hmac.c -lcrypto -ldl

aes.o: aes.c aes.h
	$(CC) -I$(INC) -L$(LIB) -c aes.c -lcrypto -ldl

ssl.o: ssl.c ssl.h
	$(CC) -I$(INC) -L$(LIB) -c ssl.c -lcrypto -ldl

clean:
	rm -rf *.o server client
