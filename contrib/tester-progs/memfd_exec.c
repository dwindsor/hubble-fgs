#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>
#include <errno.h>

int main(int argc, char *argv[], char *envp[])
{
	const char *str = "#!/bin/bash\necho Hello, world!";
	char *const args[] = { "script", NULL };
	ssize_t res;
	int fd;

	fd = memfd_create("script", 0);
	if (fd == -1) {
		perror("memfd_create");
		exit(EXIT_FAILURE);
	}

	res = write(fd, str, strlen(str));
	if (res == -1) {
		perror("write");
		exit(EXIT_FAILURE);
	}

	fexecve(fd, args, envp);
	perror("fexecve");
	exit(EXIT_FAILURE);
}