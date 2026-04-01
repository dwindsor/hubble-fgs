
GCC ?= gcc

PROGS = tcp_server tcp_client rawsock igmpquery

all: $(PROGS)

tcp_server: tcp_server.c
	$(GCC) -Wall -o tcp_server tcp_server.c

tcp_client: tcp_client.c
	$(GCC) -Wall -o tcp_client tcp_client.c

rawsock: rawsock.c
	$(GCC) -Wall -o rawsock rawsock.c

igmpquery: igmpquery.c
	$(GCC) -Wall -static -o igmpquery igmpquery.c -lnet

.PHONY: clean
clean:
	rm -f $(PROGS)
