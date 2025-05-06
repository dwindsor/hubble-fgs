#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <assert.h>
#include <liburing.h>

static int test_openat(struct io_uring *ring, const char *path, int dfd)
{
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	int ret;

	sqe = io_uring_get_sqe(ring);
	if (!sqe) {
		fprintf(stderr, "get sqe failed\n");
		goto err;
	}
	io_uring_prep_openat(sqe, dfd, path, O_RDONLY, 0);

	ret = io_uring_submit(ring);
	if (ret <= 0) {
		fprintf(stderr, "sqe submit failed: %d\n", ret);
		goto err;
	}

	ret = io_uring_wait_cqe(ring, &cqe);
	if (ret < 0) {
		fprintf(stderr, "wait completion %d\n", ret);
		goto err;
	}
	ret = cqe->res;
	io_uring_cqe_seen(ring, cqe);
	return ret;
err:
	return -1;
}

int main(int argc, char *argv[])
{
	struct io_uring ring;
	int ret;

	if (argc < 2) {
		fprintf(stderr, "Usage: %s [file name]\n", argv[0]);
		return 1;
	}

	ret = io_uring_queue_init(8, &ring, 0);
	if (ret) {
		fprintf(stderr, "ring setup failed\n");
		return 1;
	}

	ret = test_openat(&ring, argv[1], AT_FDCWD);
	if (ret < 0) {
		fprintf(stderr, "io_uring open failed\n");
        return 1;
	}

    close(ret);

	return 0;
}