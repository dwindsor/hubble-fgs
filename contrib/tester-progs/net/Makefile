
GCC ?= gcc

PROGS = tcp_server tcp_client

all: $(PROGS)

tcp_server: tcp_server.c
	$(GCC) -Wall -o tcp_server tcp_server.c

tcp_client: tcp_client.c
	$(GCC) -Wall -o tcp_client tcp_client.c

.PHONY: clean
clean:
	rm -f $(PROGS)
