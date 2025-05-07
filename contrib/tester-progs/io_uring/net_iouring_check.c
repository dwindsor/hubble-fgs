#include "net_iouring.h"
#include <stdio.h>
#include <stdlib.h>

int main()
{
	struct io_uring uring;

	if (io_uring_queue_init(64, &uring, 0) < 0) {
		exit(1);
	}
	exit(0);
}

