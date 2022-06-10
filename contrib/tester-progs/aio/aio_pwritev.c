#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <errno.h>

#include <unistd.h>
#include <fcntl.h>
#include <libaio.h>

#define BUFFER_SIZE 32

int main(int argc, char *argv[])
{
	io_context_t ctx;
	struct iocb iocb;
	struct iocb *iocbs[1];
	struct io_event events[1];
	struct timespec timeout;
	int i, fd;
	char text[BUFFER_SIZE];
	size_t len = BUFFER_SIZE;
	struct iovec vecs;

	if (argc != 2) {
		fprintf(stderr, "%s outfile\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	fd = open(argv[1], O_CREAT | O_WRONLY | O_TRUNC, 0644);
	if (fd == -1) {
		perror("open");
		exit(EXIT_FAILURE);
	}

	memset(&ctx, 0, sizeof(ctx));
	if (io_setup(10, &ctx) != 0) {
		perror("io_setup");
		exit(EXIT_FAILURE);
	}

	for (i = 0; i < BUFFER_SIZE; ++i)
		text[i] = 'A' + i;
	vecs.iov_base = text;
	vecs.iov_len = len;
	io_prep_pwritev(&iocb, fd, &vecs, 1, 0);
	iocb.data = (void *)text;

	iocbs[0] = &iocb;

	if (io_submit(ctx, 1, iocbs) != 1) {
		io_destroy(ctx);
		perror("io_submit");
		exit(EXIT_FAILURE);
	}

	while (1) {
		timeout.tv_sec = 0;
		timeout.tv_nsec = 500000000;
		if (io_getevents(ctx, 0, 1, events, &timeout) == 1) {
			close(fd);
			break;
		}
		printf("not done yet\n");
		sleep(1);
	}
	io_destroy(ctx);

	return 0;
}