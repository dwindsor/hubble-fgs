# Build with the JDK headers matching the target JVM architecture.
JAVA_HOME ?= /opt/jdk-11.0.7+10
CC ?= cc
CFLAGS ?= -O2 -fPIC -Wall -Wextra -Werror
OUT ?= libtetragon-jvm-patch.so

all: $(OUT)

$(OUT): jvm_patch.c
	$(CC) $(CFLAGS) -I$(JAVA_HOME)/include -I$(JAVA_HOME)/include/linux -shared -o $@ $<

clean:
	rm -f $(OUT)

.PHONY: all clean
