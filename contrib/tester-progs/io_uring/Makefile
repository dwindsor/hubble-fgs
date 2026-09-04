GCC ?= gcc

PROGS = cp_liburing cat_liburing write_liburing sq_poll net_iouring_check tcp_iouring_server tcp_iouring_client udp_iouring_server open_liburing

all: $(PROGS)

cp_liburing: cp_liburing.c
	$(GCC) -Wall -o cp_liburing cp_liburing.c -luring $(EXTRA_BUILD_FLAGS)

cat_liburing: cat_liburing.c
	$(GCC) -Wall -o cat_liburing cat_liburing.c -luring $(EXTRA_BUILD_FLAGS)

write_liburing: write_liburing.c
	$(GCC) -Wall -o write_liburing write_liburing.c -luring $(EXTRA_BUILD_FLAGS)

sq_poll: sq_poll.c
	$(GCC) -Wall -o sq_poll sq_poll.c -luring $(EXTRA_BUILD_FLAGS)

net_iouring_check: net_iouring_check.c
	$(GCC) -Wall -o net_iouring_check net_iouring_check.c -luring $(EXTRA_BUILD_FLAGS)

tcp_iouring_server: tcp_iouring_server.c
	$(GCC) -Wall -o tcp_iouring_server tcp_iouring_server.c -luring $(EXTRA_BUILD_FLAGS)

tcp_iouring_client: tcp_iouring_client.c
	$(GCC) -Wall -o tcp_iouring_client tcp_iouring_client.c -luring $(EXTRA_BUILD_FLAGS)

udp_iouring_server: udp_iouring_server.c
	$(GCC) -Wall -o udp_iouring_server udp_iouring_server.c -luring $(EXTRA_BUILD_FLAGS)

open_liburing: open_liburing.c
	$(GCC) -Wall -o open_liburing open_liburing.c -luring $(EXTRA_BUILD_FLAGS)

.PHONY: clean
clean:
	rm -f $(PROGS)

.PHONY: all-files
all-files:
	@printf '%s\n' $(PROGS)
