
GCC ?= gcc

PROGS = write pwrite64 writev pwritev pwritev2 read pread64 readv preadv preadv2 sendfile copy_file_range

all: $(PROGS)

write: write.c
	$(GCC) -Wall -o write write.c -static

pwrite64: pwrite64.c
	$(GCC) -Wall -o pwrite64 pwrite64.c -static

writev: writev.c
	$(GCC) -Wall -o writev writev.c -static

pwritev: pwritev.c
	$(GCC) -Wall -o pwritev pwritev.c -static

pwritev2: pwritev2.c
	$(GCC) -Wall -o pwritev2 pwritev2.c -static

read: read.c
	$(GCC) -Wall -o read read.c -static

pread64: pread64.c
	$(GCC) -Wall -o pread64 pread64.c -static

readv: readv.c
	$(GCC) -Wall -o readv readv.c -static

preadv: preadv.c
	$(GCC) -Wall -o preadv preadv.c -static

preadv2: preadv2.c
	$(GCC) -Wall -o preadv2 preadv2.c -static

sendfile: sendfile.c
	$(GCC) -Wall -o sendfile sendfile.c -static

copy_file_range: copy_file_range.c
	$(GCC) -Wall -o copy_file_range copy_file_range.c -static

.PHONY: clean
clean:
	rm -f $(PROGS)
