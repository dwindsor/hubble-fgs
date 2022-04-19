
GCC ?= gcc

PROGS = sigkill-tester capabilities-tester namespace-tester dup-tester

all: $(PROGS)

sigkill-tester: sigkill-tester.c
	$(GCC) -Wall -o sigkill-tester sigkill-tester.c

capabilities-tester: capabilities-tester.c
	$(GCC) -Wall $< -o $@ -static -lcap

namespace-tester: namespace-tester.c
	$(GCC) -Wall $< -o $@ -static

dup-tester: dup-tester.c
	$(GCC) -Wall $< -o $@ -static

.PHONY: clean
clean:
	rm -f $(PROGS)
