#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>

int main(int argc, char *argv[])
{
	int fd_in, fd_out;
	struct stat stat;
	off64_t len, ret;

	if (argc != 3) {
		printf("%s: infile outfile\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	fd_in = open(argv[1], O_RDONLY);
	if (fd_in == -1) {
		perror("open");
		exit(EXIT_FAILURE);
	}

	if (fstat(fd_in, &stat) == -1) {
		perror("fstat");
		exit(EXIT_FAILURE);
	}

	len = stat.st_size;

	fd_out = open(argv[2], O_CREAT | O_WRONLY | O_TRUNC, 0644);
	if (fd_out == -1) {
		perror("open");
		exit(EXIT_FAILURE);
	}

	do {
		ret = syscall(SYS_copy_file_range, fd_in, NULL, fd_out, NULL,
			      len, 0);
		if (ret == -1) {
			perror("copy_file_range");
			exit(EXIT_FAILURE);
		}

		len -= ret;
	} while (len > 0 && ret > 0);

	close(fd_in);
	close(fd_out);

	return 0;
}
