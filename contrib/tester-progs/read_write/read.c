#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>

int main(int argc, char *argv[])
{
	char text[16];
	int fd;
	ssize_t err;
	size_t len = 16;

	if (argc != 2) {
		fprintf(stderr, "%s infile\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	fd = open(argv[1], O_RDONLY);
	if (fd == -1) {
		perror("open");
		exit(EXIT_FAILURE);
	}

	err = syscall(SYS_read, fd, text, len);
	if (err != len) {
		perror("read");
		exit(EXIT_FAILURE);
	}

	close(fd);

	return 0;
}