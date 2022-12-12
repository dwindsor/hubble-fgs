# Hubble-FGS: The Hubble Fine Guidance Sensors

> The Fine Guidance Sensor (FGS) is an optical sensor used on the Hubble Space
> Telescope to provide pointing information for the spacecraft and as a scientific
> instrument for astrometric science

FGS is the internal name for the Cilium enterprise
([soon](https://github.com/isovalent/hubble-fgs/pull/961) to be partly
open-sourced) component that enables enhanced visibility into in-kernel
process events via eBPF.

Some of the features of FGS are:

 * Maintains the process hierarchy, and makes it available on the various
   events it generates

 * Supports a variety of different types of events
     - process events (e.g., exec)
     - network events (e.g., connect, listen, etc.)
     - protocol-specific events:
       [TLS](bpf/parsers/tls),
       [HTTP and HTTP/2](bpf/parsers/http),
       [DNS](https://github.com/isovalent/hubble-fgs/pull/895)

  * Supports generic kprobe and tracepoint events. These events are called
    "generic events" because they allow users, via a proper configuration, to
    insert functionality on arbitrary points in the kernel (mainly on
    functions/tracepoints).

    Users can define where the hooks are added (e.g., in what system calls) and
    what they do. Typically, they will generate events exported by FGS, but they
    can also take other actions (e.g., send the KILL signal). Users can also
    define what information is added into generated events (e.g., function
    arguments/return value), filters that define certain conditions of when the
    action hooks are triggerd (e.g., generate events only for specific PIDs or
    when arguments have specific values). There is also support for extracting
    information that is not available via normal means: such as the buffers of
    system calls, filenames based on fd arguments, and others.

    The configuration specification for above events can be found in the CRD
    [spec](pkg/k8s/apis/isovalent.com/client/crds/v1alpha1/cilium.io_tracingpolicies.yaml).
    There are also [examples](/crds/examples/) of how the CRD can be used to configure FGS, not
    only for the generic events, but also for other parsers (e.g., TLS).



## BTF

FGS distributes its bpf programs as object files. As a result, it depends on
proper relocations (e.g., for struct offsets) that depend on internal kernel
information. This information is encoded using
[BTF](https://facebookmicrosites.github.io/bpf/blog/2020/02/19/bpf-portability-and-co-re.html).
Have a look at [the
README](https://github.com/isovalent/hubble-builder/tree/master/fgs-btf/README.md)
of the  [hubble-builder](https://github.com/isovalent/hubble-builder/)
repository for more details.

## Execute FGS via Docker

To run docker image with custom BTF link btf in /var/lib/hubble-fgs/btf as shown
below. If BTF link is omitted hubble-fgs will attempt to search for it in the
list of known kernels using the running kernels `uname -r`. If it is still not
found an error will be reported.

To build the image with metadata use

    make image-btf

To build without metadata this will require users to include metadata manually.

    make image

To run image in docker,

    docker run --name hubble-fgs --env FGS_BTF=/var/lib/hubble-fgs/btf --env FGS_PROCFS=/procRoot/ --privileged -v /proc/:/procRoot -v /usr/lib/debug/boot/vmlinux-5.0.0-38-generic:/var/lib/hubble-fgs/btf -ti quay.io/isovalent/hubble-fgs

## Testing

### Running FGS in KVM

The `contrib/kvm` directory contains a Makefile to help you run Tetragon inside
a little-vm-helper KVM virtual machine. Consult [contrib/kvm/README.md](contrib/kvm/README.md)
for more information.

### Running FGS Locally in KinD

The scripts in `contrib/kind` can be used to run and test FGS locally in a KinD
cluster.

First, ensure that you have an up-to-date version of [Docker][docker] and [KinD][kind].

Once you have installed the necessary tooling, you can bootstrap a cluster for testing
with `contrib/kind/bootstrap-cluster.sh`.

After bootstrapping the cluster, you can install the latest FGS from source by running
`contrib/kind/install-fgs.sh`.

Finally, run the respective test case script located in `contrib/kind/tests` (for
example, `contrib/kind/tests/demo-app.sh`).

In case you need to test under a different kernel, you can use the `contrib/kvm` scripts
to bootstrap a minimal environment for running FGS in a KinD cluster (see the [previous
section](#running-fgs-in-kvm) for details).

### Testing FGS Locally Using the e2e Framework

We run FGS end-to-end tests using our e2e framework package, which is defined in
[`tests/e2e`](./tests/e2e/). The easiest way to run end-to-end tests is using a local KinD
cluster. First, ensure that you have an up-to-date version of [Docker][docker] and
[KinD][kind]. With the necessary tooling installed, you can simply run `make e2e-test` to
compile and run the e2e tests. The e2e framework will automatically bootstrap a KinD
cluster for each test, installing a local development version of FGS alongside the latest
Cilium.

Should you wish to use an alternative cluster instead of bootstrapping a local KinD
cluster, you can pass a kubeconfig like so: `make e2e-test
EXTRA_TESTFLAGS="-kubeconfig=~/.kube/config"`.

More complex test commands can be run manually by targeting the appropriate test(s) in
`tests/e2e/tests`. You can generate a skeleton command for running tests by running `make
-n e2e-test` and copying the output. An example command might look something like the
following:

```
go test -p 1 -parallel 1  -gcflags="" -timeout 20m -failfast ./tests/e2e/tests/... -fail-fast \
  -tetragon.helm.set enterprise.image.override="isovalent/hubble-fgs:latest" \
  -tetragon.helm.set hubbleEnterpriseOperator.image.override="isovalent/hubble-enterprise-operator:latest"
```

In case you want to write a new e2e test using the framework, we have provided a skeleton
file you can use as the basis for your new test, which contains some in-line documentation
in the comments. See [`tests/e2e/tests/skeleton`](./tests/e2e/tests/skeleton).

[docker]: https://docs.docker.com/engine/install/
[kind]: https://kind.sigs.k8s.io/docs/user/quick-start/

## Adding Events

Adding new events should be straight forward. We may not be there yet, but it should be
a goal. The following basic steps are needed to add a new event feature.

1. Add BPF program in ./bpf with Makefile update. When your event is ready to be
   pushed to userspace use the 'tcpmon_map' and perf_event_output helper. See an
   example in ./bpf/bpf_execve_event.c.

2. Next you will need to add an observer object in observer.go, see ObserverBind,
   ObserverExecve, etc. This part tells the golang user space to load the BPF
   program you wrote above.

   Specifically, add the object to the list of programs named observerPrograms. Additionally,
   if a pinned map is needed add it to observerMaps. If a map is not listed here each
   BPF instance will create its own copy.

3. At this point events your program will be loaded and events will be pushed from kernel
   to userspace. The next step is to write the logic to consume the event and pretty print
   it and/or push over socket to hubble or json exporter.

   Review existing event handlers in receiveEvent(). Then extend receiveEvent() with
   your event logic. The userspace event definitions are in ./pkg/client/api.go and the
   kernel side definitions are in ./bpf/lib/hubble_msg.h

   Create a pretty printer in reader pkg.

4. Teach hubble-fgs_main.go about the new bpf program.

5. TBD ship message over Unix socket currently only single type accepted will fix
   soon.


Work that would be nice to have, but is not critical yet. First we should abstract
pretty printers and message generators to an interface and include in the observer
object. This way folks creating events can completely avoid editing core code.

At the moment hubble-fgs_main.go needs a link to the program name. Reasonable defaults
should be added, so we can skip this step. It is a bit useful to replace a program
on a system with a new test program, but it's also a bit annoying on the code side.

## Running FGS

### By Building it on a Linux machine

FGS has two components to build:
  * the bpf programs under `./bpf` (written in C)
  * the agent code (written in go)

The bpf programs require to be compiled with a custom version of `clang`.
There is docker container that include binary versions the custom `clang`.

On a Linux machine, they can be installed using `make  tools-install`:

```
$ make tools-install
mkdir -p ./bin
docker cp f596be2033cba6afbb96a282efad79834967f52fd4ec85ae35b122623c575510:/usr/local/bin/clang-11 ./bin/clang
docker cp f596be2033cba6afbb96a282efad79834967f52fd4ec85ae35b122623c575510:/usr/local/bin/llc ./bin/llc
docker stop f596be2033cba6afbb96a282efad79834967f52fd4ec85ae35b122623c575510
f596be2033cba6afbb96a282efad79834967f52fd4ec85ae35b122623c575510
```

And then used to build and run FGS locally:

```
$ PATH=$(pwd)/bin:$PATH  make
...
$ sudo sh -c './hubble-fgs --hubble-lib ./bpf/objs'
```

Once the agent (`./hubble-fgs`) is running, events can be observed using the
`./hubble-enterprise` cli:

```
$ ./hubble-enterprise getevents
{"process_exec":{"process":{"exec_id":"OjMwNTIxMjQ0NzUxMDg4MDoyNTEzMjE=","pid":251321," ...
```

Or by passing an `--export-filename` flag to the agent.

### GKE

#### 1. Create a GKE cluster and Install Cilium

Follow https://docs.cilium.io/en/v1.10/gettingstarted/k8s-install-default/ to create a
GKE cluster and install Cilium. Use the following command to create a GKE cluster instead
of the one in the Cilium to get kernel version `5.10.68+`:

    export NAME="$(whoami)-$RANDOM"
    gcloud container clusters create "${NAME}" \
      --node-taints node.cilium.io/agent-not-ready=true:NoSchedule \
      --zone us-west2-a \
      --release-channel rapid \
      --image-type COS \
      --num-nodes 1 \
      --cluster-version 1.22.3-gke.700

#### 2. Install the latest FGS

To install hubble-enterprise using the latest Helm chart, run:

    helm repo add isovalent https://helm.isovalent.com
    helm install -n kube-system hubble-enterprise isovalent/hubble-enterprise \
      --version 9999.9999.9999-dev \
      --set enterprise.image.tag=latest \
      --set hubbleEnterpriseOperator.image.tag=latest \
      --set imagePullPolicy=Always

#### 3. Deploy CRD with set of recent features

Alpo testing cluster runs most Alpha/Beta features that are ready for
testing and exploratory use. For a good set of features to put you on
the cutting edge consider using a similar policy linked here,

 https://github.com/isovalent/cilium-enterprise-dogfooding/blob/main/flux/bases/tracing-policies/trace-all.yaml

### Minikube on Mac

#### 1. Check minikube version

FGS has been tested with minikube v1.15.1 on Mac using Virtualbox as the driver:

    % minikube version
    minikube version: v1.15.1
    commit: 23f40a012abb52eff365ff99a709501a61ac5876

#### 2. Start minikube

    minikube start --network-plugin=cni --memory=4096 --driver=virtualbox
    minikube ssh -- sudo mount bpffs -t bpf /sys/fs/bpf

#### 3. Install the latest FGS

    helm repo add isovalent https://helm.isovalent.com
    helm install -n kube-system --version 9999.9999.9999-dev cilium-enterprise isovalent/cilium-enterprise --set hubble-enterprise.enterprise.metadataImage.tag=minikube-current

### Verifying the Installation

The FGS container is called `enterprise`. If everything went well, you should see something like:

    kubectl logs -n cilium ds/hubble-enterprise -c enterprise
    ...
    time="2020-11-11T03:45:23Z" level=info msg="Listening for events..."

There is `export-stdout` container that prints FGS events to stdout:

    kubectl logs -n cilium ds/hubble-enterprise -c export-stdout -f

Note that the default installation comes with pre-defined event filters that exclude
certain events. If you don't see any events in `export-stdout` log, you might need to
edit `EXPORT_{ALLOW,DENY}_LIST` environment variables:

    kubectl edit ds -n cilium hubble-enterprise

### Minikube with 5.4 Kernel

This is useful for testing / demoing features that require >=5.4 kernel without having
to spin up a GKE cluster.

    vagrant up
    minikube start --driver=ssh \
      --ssh-ip-address=192.168.56.11 \
      --ssh-user=vagrant \
      --ssh-key=./.vagrant/machines/default/virtualbox/private_key

    helm repo add isovalent https://helm.isovalent.com
    helm repo update
    helm install -n kube-system cilium-enterprise isovalent/cilium-enterprise


## Developing BPF programs

### fgs-bench

For benchmarking and general low-level FGS BPF development a useful tool
is the fgs-bench, a benchmarking tool that runs FGS alongside some load,
e.g. tcp, tls, netperf, http, etc. See [docs/BENCHMARK.md](docs/BENCHMARK.md) for details and [pkg/bench](pkg/bench)
for the implementation.

### hubble-bpf-verify

One is also often hitting verifier limitations when writing BPF programs
and it's useful to be able to quickly get feedback whether or not
your latest change will pass the verifier or not. For this we've added,
"fgs-verify-programs", a script around bpftool that loads FGS BPF objects
and dumps some useful stats:

	Verifying /var/lib/hubble-fgs/bpf_skmsg.o...
	OK:
	; int bpf_sk_msg_fgs(struct sk_msg_md *skmsg)
	verification time 2663524 usec
	stack depth 200
	processed 93226 insns (limit 1000000) max_states_per_insn 16 total_states 7809 peak_states 1497 mark_read 202

You can compile the BPF objects and invoke the tool with `make hubble-bpf-verify`.
It assumes you have the right `clang` in PATH (`make clang-install` to get it to `bin/`).

### fgs vmtest

Another often arising issue is having BPF programs rejected on older kernels.
To aid with testing FGS on arbitrary kernel versions we have tooling around
qemu-kvm in `contrib/vmtest` that allows running the fgs-bench against a
kernel compiled from sources. See `contrib/vmtest/README.md` for more info.

## Troubleshooting FGS errors for developers

This section contains common error scenarios when running FGS while developing
and how to resolve them. These include errors where FGS fails to start up or
events aren't generated properly, etc.

### Kernel verifier blocks program loading or Unable to pin map: -4007

```
map_loader bpf_object__load_xattr (bpf/objs/bpf_execve_event.o): failed -4007: Kernel verifier blocks program loading
time="2022-01-20T17:20:08-08:00" level=debug msg="LoadAndPinMaps(bpf/objs/bpf_execve_event.o, /sys/fs/bpf/tcpmon/names_map, names_map)"
time="2022-01-20T17:20:08-08:00" level=fatal msg="Failed to start hubble-fgs" error="hubble-fgs, aborting could not load BPF programs: hubble-fgs, aborting could not load sensor BPF maps: failed 0 load map (): Unable to pin map: -4007 (bpf/objs/bpf_execve_event.o /sys/fs/bpf/tcpmon/names_map names_map)"
```

This can be caused by the BPF object files being compiled by an incompatible
compiler installed on your system. Try the following steps:

1. `make -j $(nproc) clean`
2. `make -j $(nproc) hubble-bpf-container`
3. `make -j $(nproc) hubble-fgs`

This will return the repository to a clean slate, compile the BPF programs with
a known working compiler, and compile FGS itself.

## More Info
 * Natalia's blog about  [container escape](https://www.isovalent.com/blog/post/2021-11-container-escape)
 * [https://docs.isovalent.com/quick-start/security_visibility.html](https://docs.isovalent.com/quick-start/security_visibility.html)
 * Talk: Join the FGS ci force side, by the Jedi master John. [Recording](https://drive.google.com/file/d/1fEtpjQoKURTHp5me78egs01cxTTVhi0Z/view?usp=sharing) and [Slides](https://docs.google.com/presentation/d/1Kw2EqHSuvPwDO5Fv6PbhlSUdTdYBWflBXVqzjqg9T6w/edit?usp=sharing).
 * Video recordings by Kornilios:
    * [FGS events and other info](https://drive.google.com/drive/folders/1ZwsXk9vEmmofhrfSOGLDSWBRIcvdrl1b)
    * [the followfd primitive for generic kprobes](https://drive.google.com/drive/folders/1Vq7GHREAEf358IikZT32uVYmGlwoWO7T)
    * [event checker demo](https://drive.google.com/drive/folders/1Gwqpv9BICP3nVoJlFBZVVqg8V7FVKaBW)
 * [Hacking on FGS](HACKING.md)
