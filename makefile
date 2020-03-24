CC=gcc
CFLAGS=
INC=/usr/local/ssl/include/
LIB=/usr/local/ssl/lib/

all: simpletun hmac.o aes.o

simpletun: simpletun.c aes.o
	$(CC) -I$(INC) -L$(LIB) -o simpletun simpletun.c aes.o -lcrypto -ldl

hmac.o: hmac.c hmac.h
	$(CC) -I$(INC) -L$(LIB) -c hmac.c -lcrypto -ldl

aes.o: aes.c aes.h
	$(CC) -I$(INC) -L$(LIB) -c aes.c -lcrypto -ldl

clean:
	rm -rf *.o simpletun
