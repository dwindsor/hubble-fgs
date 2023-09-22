# Low-level testing of Tetragon parsers

Low-level testing of Tetragon protocol parsers is required to validate that a
parser handles all edge-cases (e.g. partial, corrupted or malicious packets)
correctly.

By low-level we mean here the testing of the parser at the lowest level
possible: specifying the egress and ingress packets byte by byte and matching
on the exact bytes of the event produced by the parser BPF program.

Testing at this level also allows for a large suite of regression tests
as the test-cases are as lightweight as possible, each per-sensor suite of
tests requires loading of the programs only once and each test-case requires
a setup of a single lightweight connection.

## Layout

A Go "test" is defined by `pkg/parsertest/parser_test.go` that executes
the test-cases by
  1. starting Tetragon with the correct set of sensors
  2. creating a client and server for sending and receiving packets
  3. parsing the test-case file into an in-memory representation
  4. stepping through the test-case steps: send a packet, receive a packet,
     verify an event.

The test-cases are stored in `testdata/parser/<sensor>/`.  They are executed
in lexicographical order, grouped by sensor type.  Use `NN-` notation
(e.g. "03-tls-v1.2-ebpf.io") to keep a somewhat chronological order for the
tests and prefer to use a lower number for simpler test-cases to fail early
with the simpler case.

A separate command is implemented in `cmd/parsertest-gen` that enables
quicker iteration on the tests during development (`make hubble-bpf && parsertest-gen ...`)
and includes additional features for manipulating the test-cases.

## Test definition language

This is an informal specification for the parser test-case definition
language for the parser test cases. A custom language was chosen due
to the need to be able to represent packet data in a flexible way and
be able to extend it with higher-level concepts.

A parser test-case consists of a sequence of test steps. Each step
is specified with an upper-case keyword followed by arguments or a
match block.

The following keywords are supported:

- TAGS <tag>...:
    Test tags that affect the test execution. The "broken" tag denotes a test that is
    expected to fail and should produce a warning rather than a test error. The "udp" tag
    indicates a test that should occur over UDP instead of TCP.

- EGRESS <description>:
    A match block (see below) describing an outgoing packet. Usually parsed
    by skmsg program.

- INGRESS <description>:
    A match block for an incoming packet. Usually parsed by a skb_verdict
    program.

- EVENT <op> <description>:
    A match block for a BPF event with given op. Message structure
    defined by `bpf/lib/hubble_msg.h`.

- EVENTS:
    A block for matching multiple events in arbitrary order.
    Events are declared using `EVENT` with an op, e.g.:

      EVENTS
        EVENT HTTP
          $ 10 00 00 00
          $ 01
          ...
        END

        EVENT HTTP
          $ 10 00 00 00
          $ 02
          ...
        END
      END

- END:
    End of a match block started by EGRESS, INGRESS, EVENT or EVENTS.

- SLEEP <duration>:
    Sleep for <duration> where <duration> is a string that can be parsed by the stdlib's time.ParseDuration().
    Examples of valid durations: 1m30s, 20s, etc.


Comments are marked with `#` and they can be at the start of the line,
or at the end of the line as usual.

Match blocks are a set of lines describing how a packet or an event should
look like.  The following match clauses are supported:

- `$ 1b 01 3f 4b`   : Match hexadecimal bytes. Any number of them can be specified per line.
- `"a utf8 string"` : Match a UTF-8 string
- `2 12345 10 15`   : Match 16-bit network byte-order unsigned integers
- `4 131072 1 38`   : Match 32-bit network byte-order unsigned integers
- `h2 12345 10 15`  : Match 16-bit host byte-order unsigned integers
- `h4 131072 1 38`  : Match 32-bit host byte-order unsigned integers
- `I 127.0.0.1`     : Match an IP address
- `? 13`            : Match any N bytes (only EVENT)
- `NZ 13`           : Match N non-zero bytes (only EVENT)
- `$ 1b ?? 3f ??`   : Match hexadecimal bytes, unless `??`, which matches any byte (only EVENT).
- `A SRV_ADDR`      : Match IP of the server
- `A CLI_ADDR`      : Match IP of the client
- `A SRV_PORT`      : Match server port (network-endian)
- `A SRV_PORT_HOST` : Match server port (host's endian)
- `A CLI_PORT`      : Match client port (network-endian)
- `A CLI_PORT_HOST` : Match client port (host's endian)
