SRCS = $(wildcard *.c)

all: $(SRCS:.c=)

clean:
	rm $(SRCS:.c=)

.c:
	gcc $(CFLAGS) $< -o $@