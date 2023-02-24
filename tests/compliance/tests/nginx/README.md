# Nginx Compliance Testing

NOTE: This is currently a WIP. In particular, the developer workflow is still very rough
around the edges and, for now, we still have to do some things manually. The goal is to
automate this further in the future.

## How to Run

1. Build the Docker image for the tests.
```
make build
```
2. Load Tetragon with the correct tracing policy.
```
sudo ./hubble-fgs --hubble-lib bpf/objs --config-file tests/compliance/nginx/http_tracingpolicy.yaml
```
3. In another terminal, run the tests.
```
make run
```
