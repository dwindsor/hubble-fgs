# v1.20.0-pre.1

## Summary

Improvements / Bugfixes:

* [uprobes: reduce size of preload map](#uprobes-reduce-size-of-preload-map)
* [layer3: reduce memory footprint when unused](#layer3-reduce-memory-footprint-when-unused)

Features:

* [uprobes: function override](#uprobes-function-override)
* [grpc: persistent policies](#grpc-persistent-policies)

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
