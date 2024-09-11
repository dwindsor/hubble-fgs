#include "net_iouring.h"
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define BUFSIZE 1024
#define PORT 8001
#define ADDR "127.0.0.1"

static void signal_handler(int sig)
{
	if (sig == SIGTERM)
		exit(0);
}

int main()
{
	struct sockaddr_in server_addr = { 0 };
	struct io_uring_cqe *cqe;
	struct sigaction sigact;
	struct io_uring uring;
	uint64_t event_type;
	struct iovec iovecs;
	char *buffer;
	int fd;

	sigact.sa_handler = signal_handler;
	sigemptyset(&sigact.sa_mask);
	sigact.sa_flags = 0;
	sigaction(SIGTERM, &sigact, NULL);

	posix_memalign((void **)&buffer, BUFSIZE, BUFSIZE);

	fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (fd <= 0) {
		fprintf(stderr, "socket failed\n");
		exit(1);
	}

	if (io_uring_queue_init(64, &uring, 0) < 0) {
		fprintf(stderr, "io_uring_queue_init failed\n");
		exit(1);
	}

	snprintf(buffer, BUFSIZE, "hello");

	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(PORT);
	inet_aton(ADDR, &server_addr.sin_addr);
	// prep_connect is only available from v5.5
	if (!min_kernel_version(5, 5, 0)) {
		if (connect(fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
			fprintf(stderr, "connect failed\n");
			exit(1);
		}
		add_write_request(fd, &uring, &iovecs, buffer, strlen(buffer));
	} else {
		add_connect_request(fd, &uring, &server_addr, sizeof(server_addr));
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
		case EVENT_TYPE_CONNECT:
			add_write_request(fd, &uring, &iovecs, buffer, strlen(buffer));
			break;
		case EVENT_TYPE_WRITE:
			if (cqe->res == 0) {
				fprintf(stderr, "Empty write sent!\n");
				continue;
			}
			fprintf(stderr, "Written: '%s'\n", buffer);
			// prep_close is only available from v5.6
			if (!min_kernel_version(5, 6, 0)) {
				if (close(fd) < 0) {
					fprintf(stderr, "close failed\n");
					exit(1);
				}
				exit(0);
			} else {
				add_close_request(fd, &uring, EVENT_TYPE_CLOSE);
			}
			break;
		case EVENT_TYPE_CLOSE:
			exit(0);
		}
	}
}

