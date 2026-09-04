
GCC ?= gcc

PROGS = aio_pread aio_preadv aio_pwrite aio_pwritev

all: $(PROGS)

aio_pread: aio_pread.c
	$(GCC) -Wall -o aio_pread aio_pread.c -laio $(EXTRA_BUILD_FLAGS)

aio_preadv: aio_preadv.c
	$(GCC) -Wall -o aio_preadv aio_preadv.c -laio $(EXTRA_BUILD_FLAGS)

aio_pwrite: aio_pwrite.c
	$(GCC) -Wall -o aio_pwrite aio_pwrite.c -laio $(EXTRA_BUILD_FLAGS)

aio_pwritev: aio_pwritev.c
	$(GCC) -Wall -o aio_pwritev aio_pwritev.c -laio $(EXTRA_BUILD_FLAGS)

.PHONY: clean
clean:
	rm -f $(PROGS)

.PHONY: all-files
all-files:
	@printf '%s\n' $(PROGS)
