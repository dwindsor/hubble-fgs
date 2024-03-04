#define _GNU_SOURCE
#include <sched.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>

int main(int argc, char *argv[])
{
	extern char **environ; /* using existing envrinment */
	int fd;

	/* we need at least 3 command line arguments */
	if (argc < 3) {
		fprintf(stderr, "Usage: %s <mnt_ns> <arg0> <arg1> ... <argN>", argv[0]);
		exit(EXIT_FAILURE);
	}

	/* check maximum number of arguments as we define args with 64 entries */
	if (argc > 64) {
		fprintf(stderr, "%s supports up to 64 command line arguments", argv[0]);
		exit(EXIT_FAILURE);
	}

	/* open the mnt namespace provided by the first argument (i.e. /proc/1/ns/mnt) */
	fd = open(argv[1], O_RDONLY | O_CLOEXEC);
	if (fd == -1) {
		perror("open");
		exit(EXIT_FAILURE);
	}

	/* change the mnt namespace */
	if (setns(fd, CLONE_NEWNS) == -1) {
		perror("setns");
		exit(EXIT_FAILURE);
	}

	/*
	 * exec the fs-scanner based on its fd which is always 3.
	 * This program will always be called from Go code and we
	 * are using fsScannerCmd.ExtraFiles = []*os.File{execFd}
	 * to pass the fd of the scanner.
	 *
	 * Based on it's documentation:
	 * "ExtraFiles specifies additional open files to be inherited by the
	 * new process. It does not include standard input, standard output, or
	 * standard error. If non-nil, entry i becomes file descriptor 3+i."
	 */
	if (execveat(3, "", argv + 2, environ, AT_EMPTY_PATH) == -1) {
		perror("execveat");
		exit(EXIT_FAILURE);
	}

	return 0;
}
