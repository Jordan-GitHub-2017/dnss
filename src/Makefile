#  @author ccarlton
CC=gcc

CFLAGS=-Wall -g -pedantic 
LDFLAGS=

ALL=dnss

all:  $(ALL)

arps: dnss.o
	$(CC) $(LDFLAGS) -o $@ $^

arps.o: dnss.c
	$(CC) $(CFLAGS) -c $<

clean:
	rm -rf core* *.o *.gch $(ALL)

