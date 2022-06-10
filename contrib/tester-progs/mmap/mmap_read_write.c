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
	int madv = 0;

	if (argc < 2) {
		printf("Usage: %s infile\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	if (argc == 3)
		madv = 1;

	fd = open(argv[1], O_RDWR);
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

	map = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (map == MAP_FAILED) {
		perror("mmap");
		exit(EXIT_FAILURE);
	}

	if (madv) {
		ret = madvise(
			(void *)map, size,
			MADV_RANDOM); // by default it does some prefetching
		if (ret == -1) {
			perror("madvise");
			exit(EXIT_FAILURE);
		}
	}

	value = map[0]; // first a read page-fault
	printf("%d\n",
	       value); // just to ensure that compliler will not optimize out

	map[1024] = 8888; // then a write at the second half of the page

	ret = munmap(map, size);
	if (ret != 0) {
		perror("munmap");
		exit(EXIT_FAILURE);
	}

	close(fd);

	return 0;
}