#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <linux/if_arp.h>
#include <signal.h>
#include <netinet/tcp.h>

int fd = 0, accfd = 0;

void close_sockets()
{
	if (accfd > 0)
		close(accfd);
	if (fd > 0)
		close(fd);
}

void signal_handler(int sig)
{
	switch (sig) {
	case SIGTERM:
		printf("SIGTERM\n");
		printf("Closing sockets\n");
		close_sockets();
		exit(0);
		break;
	case SIGHUP:
		printf("SIGHUP\n");
		printf("Exiting immediately\n");
		exit(0);
	case SIGPIPE:
		printf("SIGPIPE\n");
		printf("Closing sockets\n");
		close_sockets();
		exit(0);
	}
	printf("SIGNAL: %d\n", sig);
}

void usage()
{
	printf("tcp_server <port> <iterations> <pattern>\n\n");
	printf("           pattern can consist of 'R' and 'S' for receive and send.\n");
	printf("           iterations specifies how many times to repeat pattern.\n");
	printf("           negative iterations implies forever.\n");
	printf("           SIGTERM causes graceful shutdown.\n");
	printf("           SIGHUP causes immediate exit.\n");
	exit(1);
}

void hexdump(unsigned char *b, unsigned int len)
{
        unsigned int i;

        for (i=0; i<len; i++) {
                if (i && i % 8 == 0)
                        printf(" ");
                if (i && i % 16 == 0)
                        printf("\n");
                printf("%02x ", b[i]);
        }
        printf("\n\n");
}

int main(int argc, char *argv[])
{
	char *pattern, *patt_ptr;
	unsigned char buf[1024];
	struct sigaction sigact;
	struct sockaddr_in s;
	unsigned short port;
	ssize_t buf_len;
	int iterations;
	ssize_t ret;
	int one = 1;

	if (argc < 4)
		usage();
	port = atoi(argv[1]);
	if (!port)
		usage();

	iterations = atoi(argv[2]);
	pattern = argv[3];

	sigact.sa_handler = signal_handler;
	sigemptyset(&sigact.sa_mask);
	sigact.sa_flags = 0;
	sigaction(SIGPIPE, &sigact, NULL);
	sigaction(SIGTERM, &sigact, NULL);
	sigaction(SIGHUP, &sigact, NULL);

	strcpy((char *)buf, "data\n");
	buf_len = 5;

	fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (fd < 0) {
		printf("socket() failed: %s\n", strerror(errno));
		exit(1);
	}

	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0 ||
			setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)) < 0) {
		printf("setsockopt() failed: %s\n", strerror(errno));
		exit(1);
	}

        s.sin_family = AF_INET;
        s.sin_port = htons(port);
        s.sin_addr.s_addr = 0x0100007f; // 127.0.0.1

	if (bind(fd, (struct sockaddr *)&s, sizeof(s)) < 0) {
		printf("bind() failed: %s\n", strerror(errno));
		exit(1);
	}

	if (listen(fd, 1) < 0) {
		printf("listen() failed: %s\n", strerror(errno));
		exit(1);
	}

	printf("Ready!\n");
	fflush(stdout);

	accfd = accept(fd, NULL, NULL);
	if (accfd <= 0) {
		printf("accept() failed: %s\n", strerror(errno));
		exit(1);
	}

	if (setsockopt(accfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0 ||
			setsockopt(accfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)) < 0) {
		printf("setsockopt() failed: %s\n", strerror(errno));
		exit(1);
	}


	while (iterations) {
		if (iterations > 0)
			iterations--;
		patt_ptr = pattern;
		while (*patt_ptr) {
			switch (*patt_ptr) {
			case 'R':
				ret = recv(accfd, buf, sizeof(buf), 0);
				if (ret < 0) {
					printf("recv() failed: %s\n", strerror(errno));
				} else if (!ret) {
					printf("Peer has closed\n");
					printf("Closing sockets\n");
					close_sockets();
					exit(0);
				} else {
					printf("Received %ld bytes:\n", ret);
					hexdump(buf, ret);
					buf_len = ret;
				}
				break;
			case 'S':
				ret = send(accfd, buf, buf_len, 0);
				if (ret < 0)
					printf("send() failed: %s\n", strerror(errno));
				break;
			case 'W':
				while (1) sleep(1);
			}
			patt_ptr++;
			usleep(10000);
		}
	}

	close_sockets();
	exit(0);
}
