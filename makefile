CC=gcc
CFLAGS=
INC=/usr/local/ssl/include/
LIB=/usr/local/ssl/lib/

all: simpletun

simpletun: simpletun.c
	$(CC) -I$(INC) -L$(LIB) -o simpletun simpletun.c -lcrypto -ldl

clean:
	rm -rf *.o simpletun
