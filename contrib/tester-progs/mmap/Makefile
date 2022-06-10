
GCC ?= gcc

PROGS = mmap_populate_read mmap_populate_write mmap_read mmap_write mmap_read_write mmap_write_read

all: $(PROGS)

mmap_populate_read: mmap_populate_read.c
	$(GCC) -Wall -o mmap_populate_read mmap_populate_read.c -static

mmap_populate_write: mmap_populate_write.c
	$(GCC) -Wall -o mmap_populate_write mmap_populate_write.c -static

mmap_read: mmap_read.c
	$(GCC) -Wall -o mmap_read mmap_read.c -static

mmap_write: mmap_write.c
	$(GCC) -Wall -o mmap_write mmap_write.c -static

mmap_read_write: mmap_read_write.c
	$(GCC) -Wall -o mmap_read_write mmap_read_write.c -static

mmap_write_read: mmap_write_read.c
	$(GCC) -Wall -o mmap_write_read mmap_write_read.c -static

.PHONY: clean
clean:
	rm -f $(PROGS)
