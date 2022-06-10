#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>

int main(int argc, char **argv)
{
	int err, fd;

	if (argc != 2) {
		fprintf(stderr, "%s outfile\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	fd = open(argv[1], O_CREAT | O_WRONLY | O_TRUNC, 0644);
	if (fd == -1) {
		perror("open");
		exit(EXIT_FAILURE);
	}

	err = fallocate(fd, 0, 0, 32);
	if (err == -1) {
		perror("fallocate");
		exit(EXIT_FAILURE);
	}

	close(fd);

	return 0;
}