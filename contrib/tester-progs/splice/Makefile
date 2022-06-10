
GCC ?= gcc

PROGS = splice

all: $(PROGS)

splice: splice.c
	$(GCC) -Wall -o splice splice.c -static

.PHONY: clean
clean:
	rm -f $(PROGS)
