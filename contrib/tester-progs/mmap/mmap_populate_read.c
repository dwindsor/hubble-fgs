#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
	size_t size;
	int *map = NULL;
	int value, ret, fd;
	struct stat st;

	if (argc != 2) {
		printf("Usage: %s infile\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	fd = open(argv[1], O_RDONLY);
	if (fd == -1) {
		perror("open");
		exit(EXIT_FAILURE);
	}

	ret = stat(argv[1], &st);
	if (ret == -1) {
		perror("stat");
		exit(EXIT_FAILURE);
	}
	size = st.st_size;

	map = mmap(NULL, size, PROT_READ, MAP_SHARED | MAP_POPULATE, fd, 0);
	if (map == MAP_FAILED) {
		perror("mmap");
		exit(EXIT_FAILURE);
	}

	value = map[0];
	printf("%d\n",
	       value); // just to ensure that compliler will not optimize out

	ret = munmap(map, size);
	if (ret != 0) {
		perror("munmap");
		exit(EXIT_FAILURE);
	}

	close(fd);

	return 0;
}