
GCC ?= gcc

PROGS = aio_pread aio_preadv aio_pwrite aio_pwritev

all: $(PROGS)

aio_pread: aio_pread.c
	$(GCC) -Wall -o aio_pread aio_pread.c -laio -static

aio_preadv: aio_preadv.c
	$(GCC) -Wall -o aio_preadv aio_preadv.c -laio -static

aio_pwrite: aio_pwrite.c
	$(GCC) -Wall -o aio_pwrite aio_pwrite.c -laio -static

aio_pwritev: aio_pwritev.c
	$(GCC) -Wall -o aio_pwritev aio_pwritev.c -laio -static

.PHONY: clean
clean:
	rm -f $(PROGS)
