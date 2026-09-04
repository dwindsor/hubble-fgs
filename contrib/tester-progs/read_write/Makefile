
GCC ?= gcc

PROGS = write pwrite64 writev pwritev pwritev2 read pread64 readv preadv preadv2 sendfile copy_file_range

all: $(PROGS)

write: write.c
	$(GCC) -Wall -o write write.c

pwrite64: pwrite64.c
	$(GCC) -Wall -o pwrite64 pwrite64.c

writev: writev.c
	$(GCC) -Wall -o writev writev.c

pwritev: pwritev.c
	$(GCC) -Wall -o pwritev pwritev.c

pwritev2: pwritev2.c
	$(GCC) -Wall -o pwritev2 pwritev2.c

read: read.c
	$(GCC) -Wall -o read read.c

pread64: pread64.c
	$(GCC) -Wall -o pread64 pread64.c

readv: readv.c
	$(GCC) -Wall -o readv readv.c

preadv: preadv.c
	$(GCC) -Wall -o preadv preadv.c

preadv2: preadv2.c
	$(GCC) -Wall -o preadv2 preadv2.c

sendfile: sendfile.c
	$(GCC) -Wall -o sendfile sendfile.c

copy_file_range: copy_file_range.c
	$(GCC) -Wall -o copy_file_range copy_file_range.c

.PHONY: clean
clean:
	rm -f $(PROGS)

.PHONY: all-files
all-files:
	@printf '%s\n' $(PROGS)
