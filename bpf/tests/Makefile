include ../Makefile.defs

TESTS = dns_parser_test.o
HEADERS = ../parsers/dns/dns.h ../parsers/dns/parser.h ../parsers/dns/pstree.h

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

objs/%.ll: %.c $(HEADERS)
	$(CLANG) $(CLANG_FLAGS) -I ../ -c $< -o $@

objs/%.o: objs/%.ll
	$(LLC) $(LLC_FLAGS) -filetype=obj $< -o $@

.PHONY: clean
clean:
	@$(ECHO_CLEAN)
	$(QUIET)rm -f $(OBJSDIR)*.{o,ll,i,s}

