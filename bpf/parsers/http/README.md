# Tetragon L7 HTTP Parser

This directory contains the BPF code for the Tetragon L7 HTTP Parser. This file attempts to provide comprehensive developer documentation for the HTTP parser and explain how it works.

The HTTP parser is a state machine that consumes packet data forwarded from L3/L4 sensors and parses out relevant HTTP metadata, including the request method, URL, response status code (and reason), and headers. Note: the HTTP parser currently does not support all headers, although it does support many of the important ones. Refer to [the list below](#supported-headers-and-methods) for more details.

## Table of Contents

1. [Supported Protocols and Features](#supported-http-protocols-and-features)
2. [Supported Headers and Methods](#supported-headers-and-methods)
3. [Metrics](#metrics)
4. [Testing the HTTP Parser](#testing-the-http-parser)

## Supported HTTP Protocols and Features

Features with an `x` are currently supported. Others are either planned or work in progress.

- [x] HTTP/1.0
- [x] HTTP/1.1
- [x] HTTP/2.0 (Partial)
- [ ] HTTP/3.0
- [x] Split Request Method
- [ ] Chunked Encoding
- [ ] kTLS

## Supported Headers and Methods

The following is a list of **headers** currently supported by the HTTP parser:

- `HOST`
- `USER-AGENT`
- `CONTENT-LENGTH`
- `TRANSFER-ENCODING`

The following is a list of **methods** currently supported by the HTTP parser:

- `CONNECT`
- `DELETE`
- `GET`
- `HEAD`
- `OPTIONS`
- `POST`
- `PUT`
- `PATCH`
- `TRACE`
- `PRI`
- `HTTP`

## Metrics

The HTTP parser exposes state metrics from BPF as a prometheus metric. This metric tracks how many times the parser is in a given state. Note that these states are not necessarily errors. For example, the parser could encounter a perfectly legitimate HTTP header that is not explicitly supported. In this case, parsing would continue, but we would see the `unknown_header` metric increment.

The following is a comprehensive list of possible labels for the HTTP parser state metric:

- `unknown_method`: the parser encountered a method that is not in the list of supported methods (see #supported-headers-and-methods)
- `missing_http_context`: the parser failed to get the http context for this msg
- `missing_process_info`: the parser failed to find process info for this msg
- `unknown_header`: the parser encountered a header that is not in the list of supported headers (see #supported-headers-and-methods)

## Testing the HTTP Parser

There are a number of different tests for the HTTP parser which each target a different level of the stack.

- **E2E Tests** help verify that the parser generates the expected HTTP events in the presence of sample HTTP traffic in a k8s context.
    - See `tests/e2e/tests/httptls` for details.
    - Run these tests with `make e2e-test` locally or run them in CI.
- **Unit Tests** stand up the HTTP sensor and verify that it generates the correct events under a few configurations and a sample workload.
    - See `pkg/sensors/http` for details.
    - Run these tests with `make test` locally or run them in CI.
- **Parser Tests** test the HTTP parser at a low level. They use a domain specific packet definition and event matching language to define the shape of the test and expected results. Rather than sthanding up the entire HTTP sensor, the parser tests load only the required BPF programs and check the raw messages that arrive in the perf buffer.
    - See `testdata/parser/http` and `testdata/parser/http2` for test definitions and `pkg/parsertest` for the parsertest harness itself.
    - The test definition language is documented thoroughly in `docs/PARSERTEST.md`.
    - Run these tests with `go test -exec sudo ./pkg/parsertest/...`.
- **Compliance Tests** verify that the HTTP parser does not break known-good workloads. This is particularly relevant for detecting and diagnosing issues related to bugs in the Linux kernel, which have burned us in the past. We currently leverage the nginx unit test suite for this purpose, by verifying that the tests pass with the parser loaded.
    - See `tests/compliance` for details.
    - Run these tests with `go test -exec sudo ./tests/compliance/...`.