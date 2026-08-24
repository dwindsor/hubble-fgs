include ../Makefile.defs

TESTS = dns_parser_test.o jhash_test.o flv_test.o
HEADERS = ../parsers/dns/dns.h ../parsers/dns/dns_parser.h ../parsers/dns/dns_pstree.h ../lib/jhash.h ../lib/tlsmsg.h

OBJSDIR  := objs/
OBJS := $(addprefix $(OBJSDIR),$(TESTS))
SUDO ?= sudo

.PHONY: all
all: $(OBJS)

.PHONY: test
test: $(OBJS)
	go test -exec "$(SUDO)" ../../pkg/dnsparser -v $(BPFGOTESTFLAGS)

$(OBJS): | $(OBJSDIR)

$(OBJSDIR):
	mkdir $(OBJSDIR)

objs/%.o: %.c $(HEADERS)
	$(CLANG) $(CLANG_FLAGS) -I ../ -c $< -o $@

.PHONY: clean
clean:
	@$(ECHO_CLEAN)
	$(QUIET)rm -f $(OBJSDIR)*.{o,ll,i,s}

