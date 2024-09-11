#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <ctype.h>
#include <sys/utsname.h>

#include "liburing.h"

#define EVENT_TYPE_READ 0
#define EVENT_TYPE_WRITE 1
#define EVENT_TYPE_ACCEPT 2
#define EVENT_TYPE_CLOSE_CLIENT 3
#define EVENT_TYPE_CLOSE 4
#define EVENT_TYPE_CONNECT 5

bool min_kernel_version(int kernel, int major, int minor)
{
	struct utsname buffer;
	int ver[16];
	int i = 0;
	char *p;

	if (uname(&buffer) < 0) {
		fprintf(stderr, "uname failed\n");
		return false;
	}

	p = buffer.release;
	while (*p && i < 16) {
		if (isdigit(*p)) {
			ver[i] = strtol(p, &p, 10);
			i++;
		} else {
			p++;
		}
	}

	if (ver[0] < kernel)
		return false;
	if (ver[0] > kernel)
		return true;
	if (ver[1] < major)
		return false;
	if (ver[1] > major)
		return true;
	if (ver[2] < minor)
		return false;
	return true;
}


void add_accept_request(int socket, struct io_uring *ring, struct sockaddr_in *client_addr, socklen_t *client_addr_len)
{
	struct io_uring_sqe *sqe;

	sqe = io_uring_get_sqe(ring);
	if (!sqe) {
		fprintf(stderr, "io_uring_get_sqe failed: %s\n", strerror(errno));
		return;
	}
	io_uring_prep_accept(sqe, socket, (struct sockaddr *)client_addr, client_addr_len, 0);
	io_uring_sqe_set_data(sqe, (void *)EVENT_TYPE_ACCEPT);
	io_uring_submit(ring);
}

void add_connect_request(int socket, struct io_uring *ring, struct sockaddr_in *server_addr, socklen_t server_addr_len)
{
	struct io_uring_sqe *sqe;

	sqe = io_uring_get_sqe(ring);
	if (!sqe) {
		fprintf(stderr, "io_uring_get_sqe failed: %s\n", strerror(errno));
		return;
	}
	io_uring_prep_connect(sqe, socket, (const struct sockaddr *)server_addr, server_addr_len);
	io_uring_sqe_set_data(sqe, (void *)EVENT_TYPE_CONNECT);
	io_uring_submit(ring);
}

void add_read_request(int socket, struct io_uring *ring, struct iovec *iovecs, void *buffer, uint64_t blen)
{
	struct io_uring_sqe *sqe;

	sqe = io_uring_get_sqe(ring);
	if (!sqe) {
		fprintf(stderr, "io_uring_get_sqe failed: %s\n", strerror(errno));
		return;
	}
	iovecs[0] = (struct iovec) {
		.iov_base = buffer,
		.iov_len = blen
	};
	io_uring_prep_readv(sqe, socket, iovecs, 1, 0);
	io_uring_sqe_set_data(sqe, (void *)EVENT_TYPE_READ);
	io_uring_submit(ring);
}

void add_write_request(int socket, struct io_uring *ring, struct iovec *iovecs, void *message, uint64_t mlen)
{
	struct io_uring_sqe *sqe;

	sqe = io_uring_get_sqe(ring);
	if (!sqe) {
		fprintf(stderr, "io_uring_get_sqe failed: %s\n", strerror(errno));
		return;
	}
	iovecs[0] = (struct iovec) {
		.iov_base = message,
		.iov_len = mlen
	};
	io_uring_prep_writev(sqe, socket, iovecs, 1, 0);
	io_uring_sqe_set_data(sqe, (void *)EVENT_TYPE_WRITE);
	io_uring_submit(ring);
}

void add_recv_request(int socket, struct io_uring *ring, struct msghdr *msg)
{
	struct io_uring_sqe *sqe;

	sqe = io_uring_get_sqe(ring);
	if (!sqe) {
		fprintf(stderr, "io_uring_get_sqe failed: %s\n", strerror(errno));
		return;
	}
	io_uring_prep_recvmsg(sqe, socket, msg, 0);
	io_uring_sqe_set_data(sqe, (void *)EVENT_TYPE_READ);
	io_uring_submit(ring);
}

void add_send_request(int socket, struct io_uring *ring, struct msghdr *msg)
{
	struct io_uring_sqe *sqe;

	sqe = io_uring_get_sqe(ring);
	if (!sqe) {
		fprintf(stderr, "io_uring_get_sqe failed: %s\n", strerror(errno));
		return;
	}
	io_uring_prep_sendmsg(sqe, socket, msg, 0);
	io_uring_sqe_set_data(sqe, (void *)EVENT_TYPE_WRITE);
	io_uring_submit(ring);
}

void add_close_request(int socket, struct io_uring *ring, uint64_t ty)
{
	struct io_uring_sqe *sqe;

	sqe = io_uring_get_sqe(ring);
	if (!sqe) {
		fprintf(stderr, "io_uring_get_sqe failed: %s\n", strerror(errno));
		return;
	}
	io_uring_prep_close(sqe, socket);
	io_uring_sqe_set_data(sqe, (void *)ty);
	io_uring_submit(ring);
}

