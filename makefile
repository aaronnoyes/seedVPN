CC=gcc
CFLAGS=

all: simpletun

simpletun: simpletun.c
	$(CC) -o simpletun simpletun.c

clean:
	rm -rf *.o simpletun
