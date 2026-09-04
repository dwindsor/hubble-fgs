
GCC ?= gcc

PROGS = splice

all: $(PROGS)

splice: splice.c
	$(GCC) -Wall -o splice splice.c

.PHONY: clean
clean:
	rm -f $(PROGS)

.PHONY: all-files
all-files:
	@printf '%s\n' $(PROGS)
