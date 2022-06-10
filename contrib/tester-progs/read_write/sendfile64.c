#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>

int main (int argc, char* argv[]) 
{
  int read_fd, write_fd;
  struct stat stat_buf;
  loff_t offset = 0;
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

  err = syscall(SYS_sendfile64, write_fd, read_fd, &offset, stat_buf.st_size);
  if (err == -1) {
    perror("sendfile64");
    exit(EXIT_FAILURE);
  }

  close(read_fd);
  close(write_fd);

  return 0;
}
