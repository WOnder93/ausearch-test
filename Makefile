CFLAGS=-g -W -Wall -Wundef -D_GNU_SOURCE
LIBS=-lauparse -laudit
CC=gcc
all:
	$(CC) $(CFLAGS) ausearch-test.c -o ausearch-test $(LIBS)

clean:
	rm -f ausearch-test *.o
