CC=gcc
CFLAGS=
INC=/usr/local/ssl/include/
LIB=/usr/local/ssl/lib/

all: 

hmac_test: hmac_test.c
	$(CC) -I$(INC) -L$(LIB) -o hmac_test hmac_test.c ../hmac.o -lcrypto -ldl

clean:
	rm -rf *.o
