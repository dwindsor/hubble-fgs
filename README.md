# Hubble-FGS: The Hubble Fine Guidance Sensors

"
The Fine Guidance Sensor (FGS) is an optical sensor used on the Hubble Space
Telescope to provide pointing information for the spacecraft and as a scientific
instrument for astrometric science
"

## Docker

To run docker image with custom BTF link btf in /var/lib/hubble-fgs/btf as shown
below. If BTF link is omitted hubble-fgs will attempt to search for it in the
list of known kernels using the running kernels `uname -r`. If it is still not
found an error will be reported.

To build the image with metadata use

    make image-btf

To build without metadata this will require users to include metadtata manually.

    make image

To run image in docker,

    docker run --name hubble-fgs --env FGS_BTF=/var/lib/hubble-fgs/btf --env FGS_PROCFS=/procRoot/ --privileged -v /proc/:/procRoot -v /usr/lib/debug/boot/vmlinux-5.0.0-38-generic:/var/lib/hubble-fgs/btf -ti quay.io/isovalent/hubble-fgs

## Testing

### Dependencies to compile / run / test FGS locally

Run

    make tools-install

Then you can proceed to the below instructions.

---

To build a docker image for running go tests, (note below 'docker run' pulls
in current code directory this just gets us golang and some tools needed to
run hubble-fgs go tests)

    docker build --label katafgs --tag katafgs:latest .

To test locally:

    go test .

To run tests in docker:

    docker run -ti --name test --privileged -v $GOPATH/src/github.com/isovalent/hubble-fgs:/go/src/github.com/isovalent/hubble-fgs isovalent/hubble-fgs-test

To use kata containers for testing, please have a look at
[`hubble-builder/kata-tester`](https://github.com/isovalent/hubble-builder/tree/master/kata-tester),
which is also where the [`kata-img`
script](https://github.com/isovalent/hubble-builder/blob/master/kata-tester/contrib/kata-img)
can be found.

To run tests in kata-container with hosted kernel we can use kata-img to see
which kernel is currently selected:

    $ kata-img
    * vmlinuz-bpf-next_hubble
      vmlinuz-kata-linux-4.19.125-79_hubble
      vmlinuz-kata-linux-5.4.44-79_hubble

Then the following 'docker run' command will launch above kernel and run go
tests,

    docker run --runtime=kata-runtime -ti --name test --cap-add all --ulimit memlock=-1:-1 \
        -v /var/lib/kata-containers/images/btf:/var/lib/hubble-fgs/btf \
        -v $GOPATH/src/github.com/isovalent/hubble-fgs:/go/src/github.com/isovalent/hubble-fgs \
        -v /proc:/procRoot isovalent/hubble-fgs-test

Some environment variables impact where fgs will look for procFS and BTF data.
The defaults are,

    export FGS_BTF=/var/lib/hubble-fgs/btf
    export FGS_PROCFS=/procRoot/

These are set from Dockerfile.test and will work with above 'docker run' command
but can be reconfigured if needed. Happy testing.

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
   kernel side defintions are in ./bpf/lib/hubble_msg.h

   Create a pretty printer in reader pkg.

4. Teach hubble-fgs_main.go about the new bpf program.

5. TBD ship message over Unix socket currently only single type accepted will fix
   soon.


Work that would be nice to have, but is not critical yet. First we should abstract
pretty printers and message generators to an interface and include in the observer
object. This way folks creating events can completely avoid editing core code.

At the moment hubble-fgs_main.go needs a link to the program name. Reasonable defaults
should be added so we can skip this step. It is a bit useful to replace a program
on a system with a new test program, but its also a bit annoying on the code side.

## Running FGS

### GKE

#### 1. Create a GKE cluster and Install Cilium

Follow https://docs.cilium.io/en/latest/gettingstarted/k8s-install-gke/ to create a
GKE cluster and install Cilium. You might want to specify
[`--release-channel` flag](https://cloud.google.com/kubernetes-engine/docs/concepts/release-channels)
during cluster creation depending on which kernel version you need.

#### 2. Install the latest FGS

    helm repo add isovalent https://helm.isovalent.com
    helm install -n cilium --version 9999.9999.9999-dev cilium-enterprise isovalent/cilium-enterprise --set cilium.enabled=false

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
      --ssh-ip-address=192.168.33.11 \
      --ssh-user=vagrant \
      --ssh-key=./.vagrant/machines/default/virtualbox/private_key

    helm repo add isovalent https://helm.isovalent.com
    helm repo update
    helm install -n kube-system cilium-enterprise isovalent/cilium-enterprise


## Developing BPF programs

### fgs-bench

For benchmarking and general low-level FGS BPF development a useful tool
is the fgs-bench, a benchmarking tool that runs FGS alongside some load,
e.g. tcp, tls, netperf, http, etc. See BENCHMARK.md for details and pkg/bench
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
Also required is to have libbpf.so in `lib/` (`make libbpf-install`).

### fgs vmtest

Another often arising issue is having BPF programs rejected on older kernels.
To aid with testing FGS on arbitrary kernel versions we have tooling around
qemu-kvm in `contrib/vmtest` that allows running the fgs-bench against a
kernel compiled from sources. See `contrib/vmtest/README.md` for more info.
