# Onboarding for New Team Members

A practical tour of the repo for someone who has just cloned it: what the code is, how to
build and test it, how to get onto a specific kernel, and some common pitfalls and gotchas
that may not be obvious at first.
Paths are relative to the repository root unless stated otherwise.

## 1. What this repo is

- Repo is `isovalent/hubble-fgs`. "Hubble FGS" (Fine Guidance Sensors) is the old name; it's
  Tetragon Enterprise now, but the old name is still all over the code, binaries, and paths.
- It is OSS Tetragon plus enterprise-only features: L3/L4 network events, L7 parsers (HTTP,
  TLS, DNS), file monitoring (FIM), the Application Model and a few other pieces.
- OSS lives as a git submodule at `modules/tetragon-oss/`. **Never edit it directly** from
  here: changes go upstream to `cilium/tetragon` and come back via `make oss-sync`. These days we also have automatic OSS syncs handled via GitHub actions.
- Everything is composed with `go.mod` replace directives (can be a little confusing if
  you don't realize it):
  ```
  github.com/cilium/tetragon         => ./modules/tetragon-oss   # OSS submodule
  github.com/cilium/tetragon/api     => ./api                    # EE API (superset of OSS)
  github.com/cilium/tetragon/pkg/k8s => ./pkg/k8s                # EE CRD types (superset)
  ```
  So an import of `github.com/cilium/tetragon/api/v1/tetragon` inside OSS code resolves to
  the *enterprise* API. OSS is compiled against EE protobufs and EE CRDs. That is how EE
  adds fields to `TracingPolicySpec` (`parser:`, `file:`) without forking OSS.
- Rule of thumb when reading an import: `github.com/isovalent/hubble-fgs/...` is EE code,
  `github.com/cilium/tetragon/...` is OSS code (redirected as above).
- [`docs/oss-ee-split.md`](oss-ee-split.md) is the canonical writeup.
- You can also check out [`AGENTS.md`](../AGENTS.md) which was written to give context to
  LLMs but it can serve as a decent onboarding guide for humans too.

### Basic overview of the layout (incomplete)

| Path | What |
|---|---|
| `modules/tetragon-oss/` | OSS submodule, read-only |
| `bpf/` | EE eBPF programs (`process/`, `networking/`, `file/`, `parsers/`, `tests/`) |
| `pkg/sensors/` | EE sensors: `file`, `http`, `layer3`, `sockmap`, `network`, `exec`, ... |
| `pkg/model/` | Application Model (EE-only) |
| `pkg/netpol*`, `pkg/dns*` | Network policy state (tightly coupled with the model), DNS |
| `api/` | EE gRPC API (extends OSS) |
| `pkg/k8s/` | EE CRDs |
| `cmd/tetragon`, `cmd/tetra` | agent and CLI |
| `tests/e2e/` | e2e framework |
| `contrib/kvm/` | LVH VM tooling for multi-kernel testing |
| `install/kubernetes/` | Helm charts |

## 2. First-time setup

```bash
git clone git@github.com:isovalent/hubble-fgs.git
cd hubble-fgs
make oss-init                   # git submodule update --init modules/tetragon-oss
sudo apt install libelf-dev libcap-dev libaio-dev liburing-dev libnet1-dev gcc-multilib libc6-dev-i386 pahole
```

If you want to build BPF with `LOCAL_CLANG=1` you also need a recent clang. The distro one
is usually too old:
```bash
wget https://apt.llvm.org/llvm.sh
sudo ./llvm.sh 22 # pick a recent/latest version

sudo update-alternatives --install /usr/bin/llvm-objcopy llvm-objcopy /usr/bin/llvm-objcopy-22 220
sudo update-alternatives --install /usr/bin/clang clang /usr/bin/clang-22 220
sudo update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-22 220
```

- `GOPRIVATE=github.com/isovalent` is set by `Makefile.defs`, so `go` commands go through
  the Makefile or you set it yourself. Needs SSH/token access to private isovalent repos.
- `make help` lists documented targets.
- Docker is required for a lot of targets (clang container, images, kind, helm linting).

## 3. Building

```bash
make tetragon-bpf tetragon tetra   # the three things you usually want
make                               # or: all = bpf + agent + tetra + bench + test-compile
```

- `make tetragon-bpf` compiles the BPF C. By default it runs clang **in a container**
  (`quay.io/cilium/clang:...`, a custom clang pinned in the Makefile). Pass `LOCAL_CLANG=1`
  to use your host clang instead, which is much faster but only correct if your clang is
  compatible. If BPF objects mysteriously fail to load or the verifier rejects them,
  suspect a bad host clang first and rebuild with the container.
- Output objects land in `bpf/objs/`. The agent needs `--bpf-lib bpf/objs`.
- `JOBS` defaults to `nproc`. `DEBUG=1` enables BPF debug output *and* disables Go
  optimisations (`NOOPT`/`NOSTRIP`).
- Build variants via tags: `nok8s` (no Kubernetes), `nocloud` (slim, drops cloud SDKs),
  `lseg` (customer-specific, `LSEG=1`).

Run it locally:
```bash
sudo ./tetragon --bpf-lib bpf/objs
sudo ./tetra getevents                     # in another shell
sudo ./tetragon --bpf-lib bpf/objs --log-level=debug   # or trace
```

`tetra` needs `sudo` here because of how it finds the agent. With no `--server-address`, it
reads `/var/run/tetragon/tetragon-info.json`, which the agent writes at startup, and
connects to the `unix://` socket advertised there rather than to `localhost:54321`. Both the
info file and the socket are root-owned, so an unprivileged `tetra` fails.

Log level can be changed on a running agent without a restart:
```bash
sudo kill -s SIGRTMIN+20 $(pidof hubble-fgs)   # debug
sudo kill -s SIGRTMIN+21 $(pidof hubble-fgs)   # trace
sudo kill -s SIGRTMIN+22 $(pidof hubble-fgs)   # restore
```

## 4. Testing

```bash
make test                 # deps (tester-progs, bpf, bpf-test) + Go tests. Needs sudo.
make test-nodeps          # same tests, skip rebuilding deps (this is what CI runs in the VM)
make test-nodeps-lseg     # ...with the lseg tag
make unit-test            # plain `go test ./...`, no sudo, no BPF
sudo make bpf-test        # BPF unit tests (bpf/tests)
make e2e-test             # e2e against a kind cluster
make parsertest           # L7 parser tests, see docs/PARSERTEST.md
```

- Most meaningful tests are behind the `sudo_tests` build tag and load real BPF, so they
  need root and a suitable kernel.
- Tests run `-p 1 -parallel 1 -failfast`. Serialisation is deliberate: concurrent runs
  clobber each other in the BPF filesystem. **Never run two BPF test runs at once**, even
  in different terminals. Failures will look random.
- Narrow it down while iterating:
  ```bash
  make test GO_TEST_PACKAGES=./pkg/sensors/http/... EXTRA_TESTFLAGS="-run TestFoo -v"
  make test GO_TEST_TIMEOUT=60m           # default is 20m
  ```
- `make check` runs golangci-lint (containerised unless your local version matches the
  pinned one exactly). `make format` = clang-format + gofmt. `make validate` runs
  everything including codegen and helm validation, and is slow.
- After changing protobufs or CRDs: `make codegen` / `make generate`, then `make vendor`.
  Codegen is itself vendored, so ordering matters; the Makefile targets handle it.
- `make tetragon-bpf-verify` loads the objects through bpftool and dumps verifier stats
  (insn count, stack depth). Useful before pushing BPF changes. CI also runs veristat and
  compares against the base.

## 5. KVM boxes for multi-kernel testing (LVH)

We need to test on multiple kernels quite frequently, and sometimes custom kernels built with specific flags / patches.

Two ways to do this, both using [little-vm-helper](https://github.com/cilium/little-vm-helper), depending on your preference.

### Option A: `contrib/kvm` Makefile (the friendly path)

```bash
cd contrib/kvm
make install-lvh              # go install lvh into GOPATH; once per machine
make run                      # boot VM with the image's stock kernel, daemonized
make ssh                      # ssh in as root, port 3333
make stop                     # graceful shutdown
make kill                     # if it won't die
```

Inside the VM the repo is mounted at `/host`:
```bash
cd /host
make test-nodeps              # or a narrower go test invocation
```

Variables: `KERNEL`, `IMAGE`, `SSH_PORT` (3333), `HOST_MOUNT` (repo root), `MEMORY` (4G),
`CPU` (2), `FG=1` to run in the foreground. `make help` in that dir lists them all.

### Custom kernels

`contrib/kvm/_data/kernels.json` ships bpf-next, 6.1, 5.15, 5.10, 5.4, 4.19, plus `-debug`
variants of each (KASAN, PROVE_LOCKING, DEBUG_KMEMLEAK, DEBUG_ATOMIC_SLEEP).

```bash
make fetch-kernel KERNEL=5.15         # clone from kernel.org
make build-kernel KERNEL=5.15         # configure + build (slow, first time especially)
make run KERNEL=5.15                  # boot the image with that kernel
```

Add one that isn't listed:
```bash
make add-kernel KERNEL=6.14 \
  KERNEL_URL='git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git?depth=1#linux-6.14.y'
```
The URL fragment after `#` is the branch. `depth=1` keeps the clone sane.

### Option B: raw `lvh`, matching CI exactly

Find the image tag CI is actually using (it is a datestamped tag renovate bumps):
```bash
yq '.jobs.run-tests.strategy.matrix.kernel' .github/workflows/kvm-gotests-arch.yaml
```
Current matrix: `bpf-next`, `rhel8.10`, `6.18`, `6.12`, `6.6`, `6.1`, `5.15`, `5.10`, `5.4`,
`4.19`, all at one shared datestamp. Note `contrib/kvm/Makefile` pins its own `IMAGE`
(6.1 today) which may lag the CI matrix.

```bash
lvh images pull quay.io/lvh-images/kind:6.1-20260720.023802
sudo lvh run --image _data/images/kind_6.1.qcow2 --host-mount ~/ -p 2222:22 --daemonize
ssh -p 2222 root@localhost
```

To avoid rebuilding inside the guest, cross-compile test binaries on the host:
```bash
make test-compile TEST_COMPILE=./pkg/sensors/file     # writes ./go-tests/pkg.sensors.file
```
then in the VM:
```bash
cd /host/<repo>
./go-tests/pkg.sensors.file -bpf-lib ./bpf/objs/ -test.run TestFileEnforceCreate
```

Gotcha: some tests resolve testdata via absolute host paths and blow up with
`open /home/you/<repo>/testdata/...: no such file or directory`. Quick fix in the guest:
```bash
mount --bind /host/ /home/<your-username>
```

[`docs/kvm-go-tests-reproduce.md`](kvm-go-tests-reproduce.md) has this walkthrough with real
output. Also worth reading: [`contrib/kvm/README.md`](../contrib/kvm/README.md).

### Reading CI failures

- Unit tests run in two workflows: **HubbleFGS Go Test** (`gotests.yml`) and **KVM Go
  Tests** (`kvm-gotests.yaml` -> `kvm-gotests-arch.yaml`, the full kernel x arch x
  BASE/LSEG matrix).
- KVM stdout only captures the outer runner, not the in-VM test output. For test-specific
  output, look at the HubbleFGS Go Test logs, or download the `test-output-*` artifacts
  from the KVM run.
- On failure the workflow scp's `/tmp/*.json`, `/tmp/*bugtool*`, `TestModel*` dumps out as
  artifacts. Grab those before re-running.

## 6. Committing

- Commit messages: conventional commits, 50/72 limits, `git commit -s` is mandatory (DCO).
- Commit messages in general should be descriptive:
    - Relevant current state
    - Why it needs changing
    - What change the commit brings
- PR descriptions are complementary with commits -> PR descriptions give the general
  context and overview, commit messages describe the changes
- PRs need a `release-note/*` label, plus a release-note code fence block in the body for
  user-facing changes. You should also consider assigning `kind/` and/or `area/` labels.
- Backports are manual cherry-picks with `[ upstream commit <sha> ]` in the message. See
  [`docs/backporting.md`](backporting.md).

## 7. Gotchas

**OSS submodule**
- Do not commit inside `modules/tetragon-oss/`. Fix belongs upstream in `cilium/tetragon`,
  then sync.
- Rebases and branch switches love to leave the submodule pointer dirty. `git status`
  showing a modified submodule usually means `git submodule update modules/tetragon-oss`.
- Each EE release branch tracks a *specific* OSS branch (master/main, v1.19/v1.7,
  v1.18/v1.6, v1.17/v1.5). General rule is EE minor number minus 12 equals the OSS minor number. For instance, take the 18 out of v1.18 and subtract 12 to get OSS v1.6.
- Enterprise vendors OSS. If you change OSS *and* EE together you often have to update both
  the submodule and `vendor/`, and `make codegen` rewrites vendored proto files. Commit both
  copies or CI will flag the drift.

**BPF**
- `DEBUG=1` builds can blow the 512-byte BPF stack limit in deep call chains. If a debug
  build fails to load but the normal build is fine, that's why. Generally we try to limit these cases but it can happen for various reasons.
- BPF maps declared via MapBuilder but not listed in the sensor's `Maps` get an empty
  `PinPath` and are silently duplicated instead of shared. Symptom: two sensors that should
  see the same map data don't.
- Sensor load order matters; a map's owner sensor must load first.
- Stale pins in `/sys/fs/bpf/tetragon` can survive across runs and across upgrades. If you see
  impossible map contents, unload cleanly or clear the pins.

## 8. Kubernetes-side dev loop

```bash
make kind                      # kind cluster with the EE kind-config (needed for FIM)
make kind-install-tetragon     # build images + helm install from source
make kind-install-tetragon KIND_BUILD_IMAGES=0     # skip rebuild
make kind-install-tetragon VALUES=my-values.yaml   # extra helm values
make kind-down
```

- Helm 4 (`v4.2.3`) must be on `PATH`; `check-helm-version` hard-fails otherwise.
- Bump the `inotify` sysctls per the kind known-issues doc or pods fail with "too many open
  files".
- New agent config flags need wiring into **both** helm charts (`_extensions.tpl` and
  `values.yaml`), or the flag exists but is unreachable in k8s.
- e2e: `make e2e-test`, `E2E_BUILD_IMAGES=0` to reuse images,
  `E2E_TESTS=./tests/e2e/tests/helm/skeleton` for one test. `make -n e2e-test` prints the
  raw `go test` command if you want to hand-tune it. `tests/e2e/tests/skeleton` is the
  documented template for a new test.

## 9. Relevant docs to check out

- [`README.md`](../README.md): build/run, GKE/EKS/minikube, troubleshooting.
- [`AGENTS.md`](../AGENTS.md): concise architecture + conventions summary.
- [`docs/oss-ee-split.md`](oss-ee-split.md): OSS/EE boundary and sensor map. Read this early.
- [`docs/HACKING.md`](HACKING.md): debugging, log levels, BTF-passed constants, checker test failures.
- [`docs/kvm-go-tests-reproduce.md`](kvm-go-tests-reproduce.md): reproducing a KVM CI failure locally.
- [`contrib/kvm/README.md`](../contrib/kvm/README.md): LVH workflow and custom kernels.
- [`docs/backporting.md`](backporting.md): version mapping and backport process.
- [`docs/PARSERTEST.md`](PARSERTEST.md), [`bpf/parsers/http/README.md`](../bpf/parsers/http/README.md): L7 parser testing.
- [`docs/BENCHMARK.md`](BENCHMARK.md) + [`pkg/bench`](../pkg/bench): `fgs-bench`.
