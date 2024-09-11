#include "net_iouring.h"
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <arpa/inet.h>

#define BUFSIZE 1024
#define PORT 8000

static void signal_handler(int sig)
{
	if (sig == SIGTERM)
		exit(0);
}

int main()
{
	struct sockaddr_in client_addr = { 0 };
	struct sockaddr_in addr = { 0 };
	struct msghdr msg = { 0 };
	struct io_uring_cqe *cqe;
	struct sigaction sigact;
	struct io_uring uring;
	unsigned char *buffer;
	uint64_t event_type;
	struct iovec iovecs;
	int fd;

	sigact.sa_handler = signal_handler;
	sigemptyset(&sigact.sa_mask);
	sigact.sa_flags = 0;
	sigaction(SIGTERM, &sigact, NULL);

	posix_memalign((void **)&buffer, BUFSIZE, BUFSIZE);

	fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
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

	if (io_uring_queue_init(64, &uring, 0) < 0) {
		fprintf(stderr, "io_uring_queue_init failed\n");
		printf("NotReady: %s\n", strerror(errno));
		exit(1);
	}

	iovecs = (struct iovec){
		.iov_base = buffer,
		.iov_len = BUFSIZE
	};

	msg = (struct msghdr){
		.msg_name = &client_addr,
		.msg_namelen = sizeof(client_addr),
		.msg_iov = &iovecs,
		.msg_iovlen = 1
	};

	add_recv_request(fd, &uring, &msg);
	printf("Ready\n");
	fflush(stdout);

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
		case EVENT_TYPE_READ:
			if (cqe->res == 0) {
				fprintf(stderr, "Empty read received!\n");
				continue;
			}
			buffer[cqe->res] = 0;
			fprintf(stderr, "Read: '%s'\n", buffer);
			msg.msg_iov->iov_len = cqe->res;
			add_send_request(fd, &uring, &msg);
			break;
		case EVENT_TYPE_WRITE:
			if (cqe->res == 0) {
				fprintf(stderr, "Empty write sent!\n");
				continue;
			}
			fprintf(stderr, "Written: '%s'\n", buffer);
			add_recv_request(fd, &uring, &msg);
			break;
		}
	}
}

