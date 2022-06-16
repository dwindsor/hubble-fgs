GCC ?= gcc

PROGS = cp_liburing cat_liburing write_liburing

all: $(PROGS)

cp_liburing: cp_liburing.c
	$(GCC) -Wall -o cp_liburing cp_liburing.c -luring

cat_liburing: cat_liburing.c
	$(GCC) -Wall -o cat_liburing cat_liburing.c -luring

write_liburing: write_liburing.c
	$(GCC) -Wall -o write_liburing write_liburing.c -luring

.PHONY: clean
clean:
	rm -f $(PROGS)
