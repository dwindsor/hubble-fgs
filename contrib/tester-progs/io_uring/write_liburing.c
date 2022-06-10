#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <liburing.h>

int main(int argc, char **argv)
{
	struct iovec vecs;
	struct io_uring ring;
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	int err, fd;

	if (argc != 2) {
		fprintf(stderr, "%s outfile\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	vecs.iov_base = "Writing using io_uring!\n";
	vecs.iov_len = 25;

	fd = open(argv[1], O_CREAT | O_WRONLY | O_TRUNC, 0644);
	if (fd == -1) {
		perror("open");
		exit(EXIT_FAILURE);
	}

	err = io_uring_queue_init(8, &ring, 0);
	if (err != 0) {
		perror("io_uring_queue_init");
		exit(EXIT_FAILURE);
	}

	sqe = io_uring_get_sqe(&ring);
	if (sqe == NULL) {
		perror("io_uring_get_sqe");
		exit(EXIT_FAILURE);
	}

	io_uring_prep_writev(sqe, fd, &vecs, 1, 0);

	err = io_uring_submit(&ring);
	if (err != 1) {
		perror("io_uring_submit");
		exit(EXIT_FAILURE);
	}

	io_uring_wait_cqe(&ring, &cqe);

	io_uring_cqe_seen(&ring, cqe);

	close(fd);

	return 0;
}
