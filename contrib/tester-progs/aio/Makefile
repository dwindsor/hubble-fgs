
GCC ?= gcc

PROGS = aio_pread aio_preadv aio_pwrite aio_pwritev

all: $(PROGS)

aio_pread: aio_pread.c
	$(GCC) -Wall -o aio_pread aio_pread.c -laio

aio_preadv: aio_preadv.c
	$(GCC) -Wall -o aio_preadv aio_preadv.c -laio

aio_pwrite: aio_pwrite.c
	$(GCC) -Wall -o aio_pwrite aio_pwrite.c -laio

aio_pwritev: aio_pwritev.c
	$(GCC) -Wall -o aio_pwritev aio_pwritev.c -laio

.PHONY: clean
clean:
	rm -f $(PROGS)
