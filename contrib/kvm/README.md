# New KVM Workflow for CI + Local Dev

## Requirements

- Should be fast in CI (cache pre-built image(s) and kernels somewhere, probably in a persistent GCP instance)
    - The reason we want to go with GCP in CI is because it supports nested KVM (so it would be faster than alternatives)
- Should be able to easily generate new disk images and combine them with arbitrary kernels
    - Probably need to automate generation of initrd for a given kernel / image pair
- Should work for local development
    - Pull down an existing image / kernel pair
    - Or easily generate a new one
- Should support:
    - Local dev (ssh, run FGS in minikube or kind, run unit tests and e2e tests locally in the vm)
    - Running tests + bench in CI (probably through a GCP instance we can SSH into, see above)

## Possible Options
