
GCC ?= gcc

PROGS = tcp_server tcp_client rawsock

all: $(PROGS)

tcp_server: tcp_server.c
	$(GCC) -Wall -o tcp_server tcp_server.c

tcp_client: tcp_client.c
	$(GCC) -Wall -o tcp_client tcp_client.c

rawsock: rawsock.c
	$(GCC) -Wall -o rawsock rawsock.c

.PHONY: clean
clean:
	rm -f $(PROGS)
