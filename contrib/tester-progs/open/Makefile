
GCC ?= gcc

PROGS = fallocate

all: $(PROGS)

fallocate: fallocate.c
	$(GCC) -Wall -o fallocate fallocate.c

.PHONY: clean
clean:
	rm -f $(PROGS)
