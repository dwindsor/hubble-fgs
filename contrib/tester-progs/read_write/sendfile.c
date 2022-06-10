#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/syscall.h>

int main(int argc, char *argv[])
{
	int read_fd, write_fd;
	struct stat stat_buf;
	off_t offset = 0;
	ssize_t err;

	if (argc < 3) {
		printf("%s: infile outfile\n", argv[0]);
		return 1;
	}

	read_fd = open(argv[1], O_RDONLY);
	if (read_fd == -1) {
		perror("open");
		exit(EXIT_FAILURE);
	}

	err = fstat(read_fd, &stat_buf);
	if (err == -1) {
		perror("fstat");
		exit(EXIT_FAILURE);
	}

	write_fd = open(argv[2], O_WRONLY | O_CREAT, stat_buf.st_mode);
	if (write_fd == -1) {
		perror("open");
		exit(EXIT_FAILURE);
	}

	err = syscall(SYS_sendfile, write_fd, read_fd, &offset,
		      stat_buf.st_size);
	if (err == -1) {
		perror("sendfile");
		exit(EXIT_FAILURE);
	}

	close(read_fd);
	close(write_fd);

	return 0;
}
