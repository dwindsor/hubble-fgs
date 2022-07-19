# HTTP Sensor Testing

## User Space Frame Queue (Unit Tests)

- [x] frame queue push and consume tests (frame_queue_test.go:TestFrameQueue)
- [x] frame queue wrap around (frame_queue_test.go:TestFrameQueueWrapAround)
  - [x] events in order
  - [x] events out of order

## HTTP Sensor Tests (Unit Tests)

- [x] curl http 1.1 (http_test.go:TestHttp11Curl)
- [x] curl http 2.0 prior knowledge (http_test.go:TestHttp20CurlPriorKnowledge)
  - [ ] NOTE: This test is currently disabled due to a kernel bug that makes it extremely flaky
  - [ ] fix kernel bug and re-enable test

## Parser Tests (Unit Tests)

### HTTP/1

- [x] GET request with 200 status code (testdata/parser/http/00-GET-200)
- [x] GET request with 404 status code (testdata/parser/http/01-GET-404)
- [x] POST request with 200 status code (testdata/parser/http/02-POST-200)
- [ ] length parsing
  - [ ] 1 header
  - [ ] 64 headers
  - [ ] 1024 headers
  - [ ] header count over limit
- [ ] split packet tests
  - [ ] half a header then rest later
  - [ ] one byte at a time
  - [ ] out of order
- [ ] garbage data test (maybe fuzzing?)

### HTTP/2

- [x] POST request with 200 status code (testdata/parser/http2/00-POST-200)
- [x] broken http2 upgrade (testdata/parser/http2/01-broken-upgrade)
  - [ ] NOTE: lots of TODOs left unfinished
  - [ ] finish all the TODOs
- [ ] length parsing
  - [ ] 1 header
  - [ ] 64 headers
  - [ ] 1024 headers
  - [ ] header count over limit
- [ ] split packet tests
  - [ ] half a header then rest later
  - [ ] one byte at a time
  - [ ] out of order
- [ ] garbage data test (maybe fuzzing?)

## End-To-End Tests

- [x] curl pod making a single http request
- [ ] simple web server with realistic workload
- [ ] verify http error metrics over some period of time
