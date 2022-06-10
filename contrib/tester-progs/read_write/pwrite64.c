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
	char text[] = "testdata";
	int fd;
	ssize_t err;
	size_t len;

	if (argc != 2) {
		fprintf(stderr, "%s outfile\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	fd = open(argv[1], O_CREAT | O_WRONLY | O_TRUNC, 0644);
	if (fd == -1) {
		perror("open");
		exit(EXIT_FAILURE);
	}

	len = strlen(text) + 1;
	err = syscall(SYS_pwrite64, fd, text, len, 0);
	if (err != len) {
		perror("pwrite64");
		exit(EXIT_FAILURE);
	}

	close(fd);

	return 0;
}