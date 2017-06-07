CC=gcc
CFLAGS=-Wall -lssl -lcrypto

binaries=aes_test

all: $(binaries)

aes_test: aes_test.c
	$(CC) $^ -o $@ $(CFLAGS)

clean:
	$(RM) -f $(binaries) *.o


 
