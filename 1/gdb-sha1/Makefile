CC=gcc
CFLAGS=-g -O0 -Wall -m32
LDFLAGS=-lcrypto

all: hasher

hasher.o: hasher.c

hasher: hasher.o
	$(CC) -m32 hasher.o -o hasher $(LDFLAGS)

clean:
	rm hasher hasher.o

.PHONY: clean
