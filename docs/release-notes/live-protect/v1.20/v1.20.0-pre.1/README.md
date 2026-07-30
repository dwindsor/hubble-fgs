# v1.20.0-pre.1

## Summary

Improvements / Bugfixes:

* [uprobes: reduce size of preload map](#uprobes-reduce-size-of-preload-map)
* [layer3: reduce memory footprint when unused](#layer3-reduce-memory-footprint-when-unused)

Features:

* [uprobes: function override](#uprobes-function-override)
* [grpc: persistent policies](#grpc-persistent-policies)
* [policy: apply only on specific kernels](#policy-apply-only-on-specific-kernels)
* [uprobes: apply only on specific versions of binaries](#uprobes-apply-only-on-specific-versions-of-binaries)

## Improvements / bugfixes


### uprobes: reduce size of preload map

* Issue: https://github.com/cisco-sbg-emu/live-protect/issues/21

The string preload map used in uprobes, was consuming a significant ammount of memory (~140MiB per
policy). It was configured so that memory for the entries are not preallocated, resulting in reduced
memory usage (<1MiB). For policy examples, consult
https://github.com/cisco-sbg-emu/live-protect/tree/main/examples/v1.19.0-pre.5#substring-matching.

### layer3: reduce memory footprint when unused

* Issue: https://github.com/isovalent/hubble-fgs/issues/8581

The layer3 BPF maps (socket tracking, TCP sockets, process network watermarks and ICMP tuples) were
sized at 32768 entries, and some of them were loaded at agent start up in order to track sockets
before a layer3 tracing policy is added. This consumed memory even on agents that never use layer3.
The maps are now declared with a single entry and resized from user space only when needed.

A new `--disable-layer3` switch skips the resize altogether, and the individual cache sizes can be
tuned with `--bpf-layer3-socket-cache-size`, `--bpf-tcp-socket-cache-size`,
`--bpf-udp-socket-cache-size`, `--bpf-network-watermarks-cache-size` and
`--bpf-icmp-socket-cache-size`. The equivalent Helm values live under `tetragon.layer3`.

Measured on the slim image with no policy loaded, `--disable-layer3` reduces the memory locked by
the agent's BPF maps from 54.5MiB to 34.3MiB. Layer3 tracing policies are rejected at load time
while the switch is set.

## Features

### uprobes: function override

* Issue: https://github.com/cisco-sbg-emu/live-protect/issues/11
* Documentation: https://tetragon.io/docs/concepts/tracing-policy/selectors/#override-action

This feature enables writing Tetragon policies that replace (override) all calls to a function with
another function that already exists in the binary (or library).

<details>

#### Example

Consider a binary named `replace`, resulting from the following C code:

```C
#include <stdio.h>


__attribute__ ((noinline))
void hello()
{
	printf("Hello world!\n");
}

__attribute__ ((noinline))
void hello2()
{
	printf("Hello pizza!\n");
}

int main(int argc, char *argv[])
{
	hello();
}
```

You can use the following policy:
```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: uprobe-replace
spec:
  uprobes:
  - path: "/path/to/replace"
    symbols:
    - "hello"
    selectors:
    - matchActions:
      - action: Override
        argNewSymbol: "hello2"
```

To replace calls to `hello` with calls to `hello2`.

The policy writer is responsible to ensure that the new symbol and the original symbol have
compatible calling conventions (e.g., function arguments).

Instead of a symbol, the address in the binary may also be specified.
For example:

```shell
nm /path/to/replace | grep hello2
0000000000001180 T hello2
```

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: uprobe-replace
spec:
  uprobes:
  - path: "/host/home/kkourt/src/hubble-fgs/docs/release-notes/live-protect/v1.20/v1.20.0-pre.1/replace"
    symbols:
    - "hello"
    selectors:
    - matchActions:
      - action: Override
        argNewAddr: 0x1180
```

</details>


### grpc: persistent policies

* Issue: https://github.com/cisco-sbg-emu/live-protect/issues/17
* Documentation: https://tetragon.io/docs/concepts/enforcement/persistent-grpc-policies/

Using `--persist-grpc-policies` will configure the Tetragon agent to persist policies loaded via
gRPC. When the agent restarts, the policies will be reloaded. This feature is meant to be used with
`--keep-sensors-on-exit` which instructs the agent to not remove the BPF programs when it exits.

<details>

#### Example

Start the Tetragon agent with `--keep-sensors-on-exit --release-pinned-bpf=false
--persist-grpc-policies --persist-grpc-policies-dir /var/run/tetragon/grpc-policies`.

The demo uses `/mnt/aa.txt` and a policy that blocks open calls on that file. More specifically:

```console
$ cat /mnt/aa.txt
a
$ cat pol1.yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "lsm-file-open"
spec:
  lsmhooks:
  - hook: "file_open"
    args:
      - index: 0
        type: "file"
    selectors:
    - matchArgs:
      - index: 0
        operator: "Prefix"
        values:
        - "/mnt/aa.txt"
      matchActions:
      - action: Override
        argError: -1
      - action: Post
```

Add the tracing policy. Also check that enforcement works.

```console
$ sudo ./tetra tracingpolicy add ./pol1.yaml
tracing policy "./pol1.yaml" added
$ sudo ./tetra tracingpolicy list
ID   NAME            DOMAIN   STATE     FILTERID   NAMESPACE   SENSORS       KERNELMEMORY   MODE      NPOST   NENFORCE   NMONITOR
2    lsm-file-open   grpc     enabled   0          (global)    generic_lsm   1.12 MB        enforce   0       0          0
$ sudo ls -la /var/run/tetragon/grpc-policies/
total 4
drwx------ 2 root root  60 Jul 24 19:25 .
drwxr-xr-x 4 root root 140 Jul 24 19:25 ..
-rw------- 1 root root 442 Jul 24 19:25 lsm-file-open::grpc.json
$ cat /mnt/aa.txt
cat: /mnt/aa.txt: Operation not permitted (os error 1)
```

If the Tetragon agent is terminated, the policy enforcement will continue to work (the BPF programs
are not removed).

```console
$ cat /mnt/aa.txt
cat: /mnt/aa.txt: Operation not permitted (os error 1)
```

Starting the tetragon agent, the policies installed via gRPC will be re-loaded.

```console
$ cat /mnt/aa.txt
cat: /mnt/aa.txt: Operation not permitted (os error 1)
```

And `tetra tracingpolicy list` shows that the policy is loaded.

```console
$ sudo ./tetra tracingpolicy list
ID   NAME            DOMAIN   STATE     FILTERID   NAMESPACE   SENSORS       KERNELMEMORY   MODE      NPOST   NENFORCE   NMONITOR
2    lsm-file-open   grpc     enabled   0          (global)    generic_lsm   1.12 MB        enforce   0       1          0
```

</details>

### policy: apply only on specific kernels

* Issue: https://github.com/cisco-sbg-emu/live-protect/issues/12

This feature allows users to conditionally apply a policy based on kernel build ID. If the policy is not applied, because the configured kernel build ID does not match the running kernel, then the policy's status reflects this by having state "skipped".


<details>

#### Example

The demo is run on a kernel with build-id ce6060ae99b59e73cf2d3236fbc2c5d06a1a29c9.

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "build-id-node-selector"
spec:
  nodeSelector:
    matchExpressions:
      - key: "tetragon.io/kernel-build-id"
        operator: In
        values: ["ce6060ae99b59e73cf2d3236fbc2c5d06a1a29c9"]
  kprobes:
    - call: "tcp_connect"
      syscall: false
```

After adding the above policy you can confirm that the policy was not filtered due to build-id mismatch by checking the policy status:

```console
root@kind-bpf-next:~# tetra tracingpolicy list
ID   NAME                     DOMAIN   STATE     FILTERID   NAMESPACE   SENSORS          KERNELMEMORY   MODE           NPOST   NENFORCE   NMONITOR
4    build-id-node-selector   grpc     enabled   0          (global)    generic_kprobe   501.26 kB      monitor_only   0       0          0

```

Note how the state of the policy is "enabled". If we change spec.nodeSelector.matchExpressions[0].values[0] to be `ce6060ae99b59e73cf2d3236fbc2c5d06a1a29c0` (the last nibble was changed from 9 to 0), then the status looks like:

```console
root@kind-bpf-next:~# tetra tracingpolicy list
ID   NAME                     DOMAIN   STATE     FILTERID   NAMESPACE   SENSORS   KERNELMEMORY   MODE      NPOST   NENFORCE   NMONITOR
5    build-id-node-selector   grpc     skipped   0          (global)              0 B            unknown   0       0          0

```

Note how the policy's state is "skipped".

You can verify that the policy was really skipped by initiating a connection from the host:

```console
telnet www.google.com 80
```

When the policy is skipped, initiating that connection should not cause an event to be generated. When the build-id does match the running kernel, you can see that there is an event generated.

```console
root@kind-bpf-next:~# tetra getevents -o json | jq 'select(.process_kprobe != null and .process_kprobe.policy_name == "build-id-node-selector")'
{
  "process_kprobe": {
    "process": {
      "exec_id": "a2luZC1icGYtbmV4dDo1NTM4MzUxNTI3NDE3Mzo4MzIz",
      "pid": 8323,
      "uid": 0,
      "cwd": "/root",
      "binary": "/usr/bin/telnet",
      "arguments": "www.google.com 80",
      "flags": "execve clone",
      "start_time": "2026-07-28T18:30:26.288035850Z",
      "auid": 4294967295,
      "parent_exec_id": "a2luZC1icGYtbmV4dDo1Mzg0MTkwMzE3NjE1NTo3MjUx",
      "refcnt": 1,
      "tid": 8323,
      "in_init_tree": false
    },
    "parent": {
      "exec_id": "a2luZC1icGYtbmV4dDo1Mzg0MTkwMzE3NjE1NTo3MjUx",
      "pid": 7251,
      "uid": 0,
      "cwd": "/root",
      "binary": "/bin/bash",
      "flags": "execve clone",
      "start_time": "2026-07-28T18:04:44.675938038Z",
      "auid": 4294967295,
      "parent_exec_id": "a2luZC1icGYtbmV4dDo1Mzg0MTg5NTQ3MTczMTo3MjUw",
      "tid": 7251,
      "in_init_tree": false
    },
    "function_name": "tcp_connect",
    "action": "KPROBE_ACTION_POST",
    "policy_name": "build-id-node-selector",
    "return_action": "KPROBE_ACTION_POST"
  },
  "node_name": "kind-bpf-next",
  "time": "2026-07-28T18:30:26.290082303Z",
  "node_labels": {
    "tetragon.io/arch": "amd64",
    "tetragon.io/hostname": "kind-bpf-next",
    "tetragon.io/internal-ip": "10.0.2.15",
    "tetragon.io/kernel-build-id": "ce6060ae99b59e73cf2d3236fbc2c5d06a1a29c9",
    "tetragon.io/kernel-major-version": "7",
    "tetragon.io/kernel-minor-version": "2",
    "tetragon.io/os": "linux"
  }
}

```

</details>

### uprobes: apply only on specific versions of binaries

* Issue: https://github.com/cisco-sbg-emu/live-protect/issues/2

This feature allows users to attach uprobe hooks based on the binary digest. This way, users can
attach uprobes to specific versions of binaries and reject the non-matching ones.


<details>

#### Example

Given a binary compiled in two different versions:
* `foo.c` (v1):
```C
#include <stdio.h>

int main() {
    printf("hello\n");
}
```
* `foo.c` (v2):
```C
#include <stdio.h>

int main() {
    printf("world\n");
}
```
and given their digests (sha256):
* `foo` (v1): `d26f021c34dd57c4b079688cd6dc94b13972ff1f7d6183c6f1def24c7d7044b1`
* `foo` (v2): `32024efcab97917963a0186515c7d775793902868904e52736a464f114259d3c`

We can write a policy that will attach an uprobe to `foo` (v1) and reject the uprobe on `foo.c` (v2):
```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "uprobe-digest-example"
spec:
  uprobes:
    - path: "/home/fdipierr/foo"
      symbols:
      - "main"
      binaryDigests:
        - "sha256:d26f021c34dd57c4b079688cd6dc94b13972ff1f7d6183c6f1def24c7d7044b1"
    - path: "/home/fdipierr/foo"
      symbols:
      - "main"
      binaryDigests:
        - "sha256:32024efcab97917963a0186515c7d775793902868904e52736a464f114259d3c"
      ignore:
        digestVerificationFailure: true
```

In this example, we will see that the first hook attaches only for binary version v1, and fails for v2;
the second hook, instead, will be skipped for v1 and attaches only for v2.

First scenario, `foo` v1 is used:
```console
$ tetra tracingpolicy add ~/pol.yaml
tracing policy "/home/fdipierr/pol.yaml" added

$ tetra tracingpolicy list
ID   NAME                    DOMAIN   STATE               FILTERID   NAMESPACE   SENSORS          KERNELMEMORY   MODE           NPOST   NENFORCE   NMONITOR
2    uprobe-digest-example   grpc     partially_enabled   0          (global)    generic_uprobe   1.13 MB        monitor_only   0       0          0
     SECTION   CFGIDX   DESCRIPTION          STATUS
     uprobes   0        /home/fdipierr/foo   loaded
     uprobes   1        /home/fdipierr/foo   digest_rejected
```

As you can see from the `tetra tracingpolicy list` output, the first hook is loaded, while the second is rejected because of a digest mismatch.

Now, let's try to use `foo` v2:
```console
$ tetra tracingpolicy add ~/pol.yaml
Error: failed to add tracing policy: rpc error: code = Unknown desc = policy handler 'tracing' failed loading policy 'uprobe-digest-example': spec.uprobes[0]: digest verification failed for path "/home/fdipierr/foo"

$ tetra tracingpolicy list
ID   NAME                    DOMAIN   STATE        FILTERID   NAMESPACE   SENSORS   KERNELMEMORY   MODE      NPOST   NENFORCE   NMONITOR
2    uprobe-digest-example   grpc     load_error   0          (global)              0 B            unknown   0       0          0
```

This time, since the first policy hook does not have the `ignore.digestVerificationFailure` property,
and the hook fails to attach, the policy is rejected and thus marked as `load_error`.
If we update the policy and add the `ignore.digestVerificationFailure` property, it will result in the
policy being loaded with only the second hook attached:
```console
$ tetra tracingpolicy add ~/pol.yaml
tracing policy "/home/fdipierr/pol.yaml" added

$ tetra tracingpolicy list
ID   NAME                    DOMAIN   STATE               FILTERID   NAMESPACE   SENSORS          KERNELMEMORY   MODE           NPOST   NENFORCE   NMONITOR
3    uprobe-digest-example   grpc     partially_enabled   0          (global)    generic_uprobe   1.13 MB        monitor_only   0       0          0
     SECTION   CFGIDX   DESCRIPTION          STATUS
     uprobes   0        /home/fdipierr/foo   digest_rejected
     uprobes   1        /home/fdipierr/foo   loaded
```

</details>