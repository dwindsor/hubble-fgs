// Inspired from https://unixism.net/loti/tutorial/sq_poll.html
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <liburing.h>
#include <string.h>

#define BUF_SIZE 512
#define STR1	 "What is this life if, full of care,\n"
#define STR2	 "We have no time to stand and stare."

int start_sq_polling_ops(const char *filename, struct io_uring *ring)
{
	int fds[2];
	char buff1[BUF_SIZE];
	char buff2[BUF_SIZE];
	char buff3[BUF_SIZE];
	char buff4[BUF_SIZE];
	struct io_uring_sqe *sqe;
	struct io_uring_cqe *cqe;
	int str1_sz = strlen(STR1);
	int str2_sz = strlen(STR2);

	fds[0] = open(filename, O_RDWR | O_TRUNC | O_CREAT, 0644);
	if (fds[0] < 0) {
		perror("open");
		exit(1);
	}

	memset(buff1, 0, BUF_SIZE);
	memset(buff2, 0, BUF_SIZE);
	memset(buff3, 0, BUF_SIZE);
	memset(buff4, 0, BUF_SIZE);
	strncpy(buff1, STR1, str1_sz);
	strncpy(buff2, STR2, str2_sz);

	int ret = io_uring_register_files(ring, fds, 1);
	if (ret) {
		fprintf(stderr, "Error registering buffers: %s\n", strerror(-ret));
		exit(1);
	}

	sqe = io_uring_get_sqe(ring);
	if (!sqe) {
		fprintf(stderr, "Could not get SQE.\n");
		exit(1);
	}
	io_uring_prep_write(sqe, 0, buff1, str1_sz, 0);
	sqe->flags |= IOSQE_FIXED_FILE;

	sqe = io_uring_get_sqe(ring);
	if (!sqe) {
		fprintf(stderr, "Could not get SQE.\n");
		exit(1);
	}
	io_uring_prep_write(sqe, 0, buff2, str2_sz, str1_sz);
	sqe->flags |= IOSQE_FIXED_FILE;

	io_uring_submit(ring);

	for (int i = 0; i < 2; i++) {
		int ret = io_uring_wait_cqe(ring, &cqe);
		if (ret < 0) {
			fprintf(stderr, "Error waiting for completion: %s\n",
				strerror(-ret));
			exit(1);
		}
		/* Now that we have the CQE, let's process the data */
		if (cqe->res < 0) {
			fprintf(stderr, "Error in async operation: %s\n", strerror(-cqe->res));
		}
		io_uring_cqe_seen(ring, cqe);
	}

	sqe = io_uring_get_sqe(ring);
	if (!sqe) {
		fprintf(stderr, "Could not get SQE.\n");
		exit(1);
	}
	io_uring_prep_read(sqe, 0, buff3, str1_sz, 0);
	sqe->flags |= IOSQE_FIXED_FILE;

	sqe = io_uring_get_sqe(ring);
	if (!sqe) {
		fprintf(stderr, "Could not get SQE.\n");
		exit(1);
	}
	io_uring_prep_read(sqe, 0, buff4, str2_sz, str1_sz);
	sqe->flags |= IOSQE_FIXED_FILE;

	io_uring_submit(ring);

	for (int i = 0; i < 2; i++) {
		int ret = io_uring_wait_cqe(ring, &cqe);
		if (ret < 0) {
			fprintf(stderr, "Error waiting for completion: %s\n", strerror(-ret));
			return 1;
		}
		/* Now that we have the CQE, let's process the data */
		if (cqe->res < 0) {
			fprintf(stderr, "Error in async operation: %s\n", strerror(-cqe->res));
		}
		io_uring_cqe_seen(ring, cqe);
	}

	if (memcmp(buff1, buff3, BUF_SIZE)) {
		fprintf(stderr, "buff1 != buff3\n");
		exit(1);
	}
	if (memcmp(buff2, buff4, BUF_SIZE)) {
		fprintf(stderr, "buff2 != buff4\n");
		exit(1);
	}
	return 0;
}

int main(int argc, char *argv[])
{
	struct io_uring ring;
	struct io_uring_params params;

	if (argc < 2) {
		fprintf(stderr, "Usage: %s [file name]\n", argv[0]);
		return 1;
	}

	memset(&params, 0, sizeof(params));
	params.flags |= IORING_SETUP_SQPOLL;
	params.sq_thread_idle = 2000;

	int ret = io_uring_queue_init_params(8, &ring, &params);
	if (ret) {
		fprintf(stderr, "Unable to setup io_uring: %s\n", strerror(-ret));
		return 1;
	}
	start_sq_polling_ops(argv[1], &ring);
	io_uring_queue_exit(&ring);
	return 0;
}
