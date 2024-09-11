#include "net_iouring.h"
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>

#define BUFSIZE 1024
#define PORT 8000

static void signal_handler(int sig)
{
	if (sig == SIGTERM)
		exit(0);
}

int main()
{
	socklen_t client_addr_len = sizeof(struct sockaddr_in);
	struct sockaddr_in client_addr = { 0 };
	struct sockaddr_in addr = { 0 };
	struct io_uring_cqe *cqe;
	struct sigaction sigact;
	struct io_uring uring;
	unsigned char *buffer;
	uint64_t event_type;
	struct iovec iovecs;
	int fd, client_fd;

	sigact.sa_handler = signal_handler;
	sigemptyset(&sigact.sa_mask);
	sigact.sa_flags = 0;
	sigaction(SIGTERM, &sigact, NULL);

	posix_memalign((void **)&buffer, BUFSIZE, BUFSIZE);

	fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (fd <= 0) {
		fprintf(stderr, "socket failed\n");
		printf("NotReady: %s\n", strerror(errno));
		exit(1);
	}

	addr.sin_family = AF_INET;
	addr.sin_port = htons(PORT);
	if (bind(fd, (const struct sockaddr *)&addr, sizeof(addr)) < 0) {
		fprintf(stderr, "bind failed\n");
		printf("NotReady: %s\n", strerror(errno));
		exit(1);
	}

	if (listen(fd, 1) < 0) {
		fprintf(stderr, "listen failed\n");
		printf("NotReady: %s\n", strerror(errno));
		exit(1);
	}

	if (io_uring_queue_init(64, &uring, 0) < 0) {
		fprintf(stderr, "io_uring_queue_init failed\n");
		printf("NotReady: %s\n", strerror(errno));
		exit(1);
	}

	client_fd = 0;

	printf("Ready\n");
	fflush(stdout);

	// prep_accept is only available from v5.5
	if (!min_kernel_version(5, 5, 0)) {
		client_fd = accept(fd, NULL, NULL);
		if (client_fd < 0) {
			fprintf(stderr, "accept failed\n");
			exit(1);
		}
		add_read_request(client_fd, &uring, &iovecs, buffer, BUFSIZE);
	} else {
		add_accept_request(fd, &uring, &client_addr, &client_addr_len);
	}

	while (1) {
		if (io_uring_wait_cqe(&uring, &cqe) < 0) {
			fprintf(stderr, "io_uring_wait_cqe failed\n");
			exit(1);
		}
		io_uring_cqe_seen(&uring, cqe);
		event_type = cqe->user_data;
		if (cqe->res < 0) {
			fprintf(stderr, "async request failed: %d for event: %ld\n", cqe->res, event_type);
			exit(1);
		}
		switch (event_type) {
		case EVENT_TYPE_ACCEPT:
			client_fd = (int)cqe->res;
			add_read_request(client_fd, &uring, &iovecs, buffer, BUFSIZE);
			break;
		case EVENT_TYPE_READ:
			if (cqe->res == 0) {
				fprintf(stderr, "Empty read received!\n");
				continue;
			}
			buffer[cqe->res] = 0;
			fprintf(stderr, "Read: '%s'\n", buffer);
			add_write_request(client_fd, &uring, &iovecs, buffer, cqe->res);
			break;
		case EVENT_TYPE_WRITE:
			if (cqe->res == 0) {
				fprintf(stderr, "Empty write sent!\n");
				continue;
			}
			fprintf(stderr, "Written: '%s'\n", buffer);
			// prep_close is only available from v5.6
			if (!min_kernel_version(5, 6, 0)) {
				if (close(client_fd) < 0) {
					fprintf(stderr, "close client failed\n");
					exit(1);
				}
				if (close(fd) < 0) {
					fprintf(stderr, "close server failed\n");
					exit(1);
				}
				exit(0);
			} else {
				add_close_request(client_fd, &uring, EVENT_TYPE_CLOSE_CLIENT);
			}
			break;
		case EVENT_TYPE_CLOSE_CLIENT:
			add_close_request(fd, &uring, EVENT_TYPE_CLOSE);
			break;
		case EVENT_TYPE_CLOSE:
			exit(0);
		}
	}
}

