# File Integrity Monitoring (FIM)

Tetragon Enterprise supports File Integrity Monitoring (FIM). Users define the paths that need to monitor. Paths can be files or directories and may reside either at the host or inside pod containers. By default, Tetragon will generate an event when the defined files are accessed. Moreover, users can define certain accesses to be blocked.

***FIM can be also used in bare-metal hosts outside of K8s.***

## How to enable FIM?

To enable FIM the user should use a TracingPolicy similar to the one below. This policy monitors only host files. For pod file monitoring, see [here](#monitoring-pod-files).

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "host-file-monitoring"
spec:
  file:
    file_paths:
    - "/etc/"
    - "/var/testfile"
    file_paths_exclude:
    - "/etc/demo1"
    - "/etc/locale.alias"
    monitorHostFiles: true
```

To enable FIM, the user should provide at least one path under `spec.file.file_paths`. This field defined prefixes to be monitored, while `spec.file.file_paths_exclude` excludes prefixes (e.g., to reduce the amount of events). If `spec.file.monitorHostFiles` is `true` we monitor host files. This can affect monitoring of pod files as described [here](#monitoring-pod-files).

Path filtering is prefix based. This means that the previous TracingPolicy will generate events for all file paths that start with `/etc/` excluding the prefix `/etc/demo1`. This will also exclude `/etc/demo10` which has the same exclude prefix. Deleting a file and creating that again will not affect the filtering on that.

### Limitations

The user can specify prefixes up to `256` characters. This is not a limitation for file/directory paths that we monitor. Furthermore, the sum of `spec.file.file_paths` and `spec.file.file_paths_exclude` entries should not exceed `4096`. Finally, the total number of all files that we monitor should not exceed `128K` and the total number of all directories that we monitor should not exceed `128K`. Except from the length of the prefixes, the rest can be easily increased depending on the user case.

## Event format

A FIM event has the following structure (we omit `process_file.process` and `process_file.parent` fields as these are similar to other events, an example full event is [here](https://gist.github.com/tpapagian/598a7e8593ff92fefbbe10b0903910a7)):

```json
{
  "process_file": {
      "process": {},
      "parent": {},
      "action": "FILE_READ",
      "args": {
        "generic_arg": {
          "file": {
            "filename": "/etc/passwd",
            "inode": {
              "number": "2575",
              "fs": {
                "name": "ext4",
                "dev": "8:1",
                "id": "sda1",
                "uuid": "5b8e9b9c-a139-4214-973c-339a7e39ed55"
              }
            },
            "parent_inode": {
              "number": "43",
              "fs": {
                "name": "ext4",
                "dev": "8:1",
                "id": "sda1",
                "uuid": "5b8e9b9c-a139-4214-973c-339a7e39ed55"
              }
            },
            "location": {
              "type": "HOST_FILE"
            }
          },
          "mnt_ns": {
            "inum": 4026531841,
            "is_host": true
          }
        }
      },
      "time": "2023-05-26T08:52:13.913993732Z",
      "hook": "security_file_permission",
      "operation": [
        "FILE_OP_POST"
      ]
    },
    "time": "2023-05-26T08:52:13.913990890Z"
}
```

FIM generates `process_file` events. Except from `process`, `parent`, `time`, and `node_name` fields that are similar to other events, it also includes some new fields.

These include:

1. `action` is the type of the operations (i.e. `FILE_READ`, `FILE_WRITE`, `FILE_DELETE`, `FILE_CREATE`, `FILE_RMDIR`, `FILE_MKDIR`, `FILE_READDIR`, `FILE_RENAME` and `FILE_CHATTR`. We provide [here](#supported-actions) more details on these actions).
2. `args.generic_arg.file.filename` is the full path of the file that is related to this event.
3. `args.generic_arg.file.inode.number` is the inode number of the file/directory shown in the `filename`.
4. `args.generic_arg.file.inode.fs` is the file system details of the file/directory shown in the `filename`.
5. `args.generic_arg.file.parent_inode.number` is the inode number of the parent directory (i.e. the directory that contains the file/directory that we care).
6. `args.generic_arg.file.parent_inode.fs` is the file system details of the parent directory.
7. `args.generic_arg.file.location` is the file location. Possible values for the `args.generic_arg.file.location.type` are:

- `HOST_FILE` the file is monitored as a host file, and the access happened from a container or the host.
- `CONTAINER_FILE_LOCAL` the file is monitored as a container file (`location.container_id` shows the container id), and the access happened from the same container.
- `CONTAINER_FILE_REMOTE` the file is monitored as a container file (`location.container_id` shows the container id), and the access happened from a different container or the host.

8. `args.generic_arg.file.mnt_ns.inum` is the mnt namespace of the process at the time of the event. `mnt_ns.is_host` is true, if this is the host mnt namespace.
9. `args.time` is the time of the event.
10. `args.hook` is the kernel function that generates the event (mainly for debugging).
11. `args.operation` is the operation of this event. Possible values are:

- `FILE_OP_POST` we report this access.
- `FILE_OP_BLOCK` we block this access (application will receive an error). More details about enforcement can be found [here](#enforcement).

A `FILE_RENAME` event has a slightly different format. An example is (we omit `process_file.process` and `process_file.parent` fields as these are similar to other events, an example full event is [here](https://gist.github.com/tpapagian/766b8fdf926a86c2ab10ff2ebb490762)):

```json
{
  "process_file": {
    "process": {},
    "parent": {},
    "action": "FILE_RENAME",
    "args": {
      "rename_arg": {
        "src": {
          "filename": "/etc/testfile.txt",
          "inode": {
            "number": "1951",
            "fs": {
              "name": "ext4",
              "dev": "8:1",
              "id": "sda1",
              "uuid": "5b8e9b9c-a139-4214-973c-339a7e39ed55"
            }
          },
          "parent_inode": {
            "number": "43",
            "fs": {
              "name": "ext4",
              "dev": "8:1",
              "id": "sda1",
              "uuid": "5b8e9b9c-a139-4214-973c-339a7e39ed55"
            }
          },
          "location": {
            "type": "HOST_FILE"
          }
        },
        "dst": {
          "filename": "/etc/testfile.dat",
          "inode": {},
          "parent_inode": {
            "number": "43",
            "fs": {
              "name": "ext4",
              "dev": "8:1",
              "id": "sda1",
              "uuid": "5b8e9b9c-a139-4214-973c-339a7e39ed55"
            }
          },
          "location": {
            "type": "HOST_FILE"
          }
        },
        "mnt_ns": {
          "inum": 4026531841,
          "is_host": true
        },
        "flags": [
          "MOVE_INTERNALLY",
          "SRC_REG_FILE",
          "DST_NOT_EXISTS"
        ]
      }
    },
    "time": "2023-05-26T08:52:03.883139944Z",
    "hook": "vfs_rename",
    "operation": [
      "FILE_OP_POST"
    ]
  },
  "time": "2023-05-26T08:52:03.883137717Z"
}
```

This event contains `rename_arg` instead of `generic_arg` in order to provide details about both the source and destination in the rename operation. More specifically:

1. `args.rename_arg.src` is similar to `args.generic_arg.file` described in the previous event, but this is related to source file/directory.
2. `args.rename_arg.dst` is similar to `args.generic_arg.file` described in the previous event, but this is related to destination file/directory.
3. `args.rename_arg.mnt_ns` is similar to `args.generic_arg.file.mnt_ns` described in the previous event.
4. `args.rename_arg.flags` contains details about the rename operation. These flags can be:
    - `MOVE_INSIDE` both source and destination file/directory are inside a watched directory.
    - `MOVE_OUTSIDE` source file/directory is inside a watched directory but destination is not.
    - `MOVE_INTERNALLY` source file/directory is not inside a watched directory but destination is.
    - `SRC_REG_FILE` source is a file.
    - `SRC_DIRECTORY` source is a directory.
    - `DST_NOT_EXISTS` destination name does not exist (will create it).
    - `DST_REG_FILE` destination is a file (already exists).
    - `DST_DIRECTORY` destination is a directory (already exists).

5. `args.time` is similar to `args.time` described in the previous event.
6. `args.hook` is similar to `args.hook` described in the previous event.
7. `args.operation` is similar to `args.operation` described in the previous event.

## Supported Actions

1. ### `FILE_READ`/`FILE_WRITE`

    These are events for accessing or modifying files inside a watched path. To the best of our knowledge, Tetragon's FIM implementation, transparently handles all different ways to file I/O.

    There are CI jobs that ensure that we generate events for the following ways to do I/O:

    - Using `read`/`write` family system calls. These include: `read`, `readv`, `pread64`, `preadv`, `preadv2`, `write`, `writev`, `pwrite64`, `pwritev`, and `pwritev2` system calls.
    - Optimized ways to copy files inside kernel. These include: `copy_file_range`, `sendfile`, and `splice` system calls.
    - Asynchronous ways to do I/O. These include [`io_uring`](https://man.archlinux.org/man/io_uring.7.en) and [`aio`](https://man7.org/linux/man-pages/man7/aio.7.html).
    - File access through memory-mapped files (i.e. `mmap`). Also check [here](#mmap-events) for details and limitation on generated events.
    - `fallocate` and `truncate` system calls, and their variants.

2. ### `FILE_CREATE`

    These are events for creating files inside a watched path.

3. ### `FILE_DELETE`

    These are events for deleting files inside a watched path.

4. ### `FILE_MKDIR`

    These are events for creating directories inside a watched path.

5. ### `FILE_RMDIR`

    These are events for deleting directories inside a watched path.

6. ### `FILE_RENAME`

    These are events for renaming (mv) files/directories inside/outside a watched path.

7. ### `FILE_READDIR`

    These are events for listing the contents of a directory inside a watched path.

8. ### `FILE_CHATTR`

   These are events for changing permissions/uid/gid (i.e. `chmod`, `chown` system calls) for files/directories inside a watched path.

9. ### `FILE_EXEC`

   These are events for executing a file inside a watched path.

FIM requires a kernel version of 4.19 or later (exception is RedHat/OpenShift 4.18 kernels, check [here](#using-fim-in-openshiftrethat-418-kernels)). Our tests cover all above on 4.19, 5.4, 5.10, and 5.15 kernels (longterm releases). We do not plan to support older kernels.

## Monitoring Pod Files

FIM also supports monitoring for K8s pod files. Users can select pods to be monitored based on the namespace and pod name using the `podSelector` field.

An example TracingPolicy that enables pod file monitoring is:

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "host-pod-file-monitoring"
spec:
  file:
    file_paths:
    - "/etc/"
    - "/var/testfile"
    file_paths_exclude:
    - "/etc/demo1"
    - "/etc/locale.alias"
    monitorHostFiles: true
    podSelector:
      matchExpressions:
      - key: "k8s:io.kubernetes.pod.namespace"
        operator: "In"
        values:
        - "default"
        - "ubuntu"
```

Users can use `monitorHostFiles` to define if this tracing policy should also include host files. The default value of `monitorHostFiles` in K8s is `true`. When loading the policy with a switch or via gRPC, the default value of `monitorHostFiles` is `false`. Thus, the user should specify `monitorHostFiles: true` in order to monitor host files.

Using the previous example we will monitor host and pod files that have `[pod_namespace == "default" OR pod_namespace == "ubuntu"]`. The exact files that we care about, are defined using `file_paths` and `file_paths_exclude`, similar to what we described in the previous sections.

For now, valid keys are `"k8s:io.kubernetes.pod.namespace"`, `"io.kubernetes.pod.namespace"`, `"k8s:io.kubernetes.pod.app"`, and `"io.kubernetes.pod.app"`. Valid operators are `"In"` and `"NotIn"`. In the case of `"k8s:io.kubernetes.pod.namespace"` and `"io.kubernetes.pod.namespace"` we do a full match check. In the case of `"k8s:io.kubernetes.pod.app"`, and `"io.kubernetes.pod.app"` we do a prefix check, which also matches in the case of full match.

### Other examples

```yaml
podSelector:
  matchExpressions:
  - key: "k8s:io.kubernetes.pod.namespace"
    operator: "In"
    values:
    - "default"
  - key: "k8s:io.kubernetes.pod.app"
    operator: "In"
    values:
    - "ubuntu"
```

This monitors pod files with `[pod_namespace == "default" AND pod_name == "ubuntu"]`.

```yaml
podSelector:
  matchExpressions:
  - key: "io.kubernetes.pod.namespace"
    operator: "NotIn"
    values:
    - "kube-system"
```

This monitors pod files with `[pod_namespace != "kube-system"]`.

```yaml
podSelector:
  matchExpressions:
  - key: "io.kubernetes.pod.namespace"
    operator: "In"
    values:
    - "default"
    - "test"
  - key: "io.kubernetes.pod.app"
    operator: "In"
    values:
    - "ubuntu"
```

This monitors pod files with `[(pod_namespace == "default" OR pod_namespace == "test") AND pod_name == "ubuntu"]`.

```yaml
podSelector: {}
```

This monitors all pods (including the pod that runs Tetragon Enterprise).

We also support `matchLabels` under `podSelector` in order to be consistent with K8s common practices and Cilium. An example is:

```yaml
podSelector:
  matchLabels:
    "k8s:io.kubernetes.pod.namespace": "default"
    "k8s:io.kubernetes.pod.app": "ubuntu"
```

This monitors pod files with `[pod_namespace == "default" AND pod_name == "ubuntu"]`.

Generally, `matchExpressions` is a superset of `matchLabels`. We can also have both `matchExpressions` and `matchLabels` under `podSelector` and in that case the results of these will be `AND`ed.

The structure of the events related to pod files is the same as described in a [previous](#event-format) section. Examples for these events can be found [here](https://gist.github.com/tpapagian/a753e75543098d5b67f3120a04f5e2b5).

## Event Selector

FIM provides event selectors in order to reduce the number of generated events. An example TracingPolicy is:

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "file-monitoring-selectors"
spec:
  file:
    file_paths:
    - "/etc/"
    - "/var/testfile"
    file_paths_exclude:
    - "/etc/demo1"
    - "/etc/demo2"
    - "/etc/locale.alias"
    monitorHostFiles: true
    selectors:
    - matchBinaries:
      - operator: "In"
        values:
        - "/usr/bin/mybinary"
      matchOperations:
      - operator: "In"
        values:
        - "FILE_DELETE"
        - "FILE_WRITE"
      matchActions:
      - action: Post
```

This will generate events when `[process.binary == /usr/bin/mybinary] AND [(action == FILE_DELETE) OR (action == FILE_WRITE)]`.

We support the following filters:

- `matchBinaries` filters events based on `process.binary`. Valid operators are `"In"` and `"NotIn"`. Values are arbitrary strings with size less than 255 characters. The maximum number of values can be 256.

- `matchOperations` filters events based on `action`. Valid operators are `"In"` and `"NotIn"`. Valid values are all actions listed [here](#supported-actions).

- `matchActions` defines the action to be taken. Valid actions are `Post` and `Block` (default is `Post`). `Post` generates an event. `Block` blocks the operation (application will receive an error) and generates an event. More on enforcement can be found [here](#enforcement).

Different filters inside a single selector are `AND`ed. Different selectors are `OR`ed.

## Enforcement

Tetragon's FIM provides support for enforcement. This means that it can block specific operations. To enable that, you should use:

```yaml
selectors:
- matchActions:
  - action: Block
```

An example TracingPolicy is:

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "file-monitoring-enforcement"
spec:
  file:
    file_paths:
    - "/etc/"
    monitorHostFiles: true
    podSelector:
      matchExpressions:
      - key: "k8s:io.kubernetes.pod.namespace"
        operator: "In"
        values:
        - "kube-system"
    selectors:
    - matchOperations:
      - operator: "In"
        values:
        - "FILE_DELETE"
        - "FILE_RMDIR"
        - "FILE_RENAME"
      matchActions:
      - action: Block
```

This will block all file delete, directory delete, and rename operations inside `/etc/` for the host and all K8s pods inside the `kube-system` namespace.

Enforcement uses `lsm` or `fmod_ret` eBPF programs (based on the kernel's supported features). Because of this, enforcement requires kernels >= 5.6.

### Ensuring that enforcement is enabled

After loading a TracingPolicy with enforcement (i.e. `action: Block`), you will see something similar in the logs:
```
time="2023-05-26T11:51:10Z" level=info msg="probeTracingModifyReturn() = true"
time="2023-05-26T11:51:11Z" level=info msg="HaveProgramType(ebpf.Tracing) = true"
time="2023-05-26T11:51:11Z" level=info msg="probeLSM() = true (enabled = true)"
time="2023-05-26T11:51:11Z" level=info msg="HaveProgramType(ebpf.LSM) = true"
time="2023-05-26T11:51:11Z" level=info msg="Loading file hooks for enforce with lsm"
```

If the last message is `Loading file hooks for enforce with XXX` then FIM enforcement has successfully enabled. `XXX` can be either `lsm` or `fmod_ret`.

Otherwise, a message similar to `Loading file hooks for observe` will appear in the logs. In that case, `action: Block` will be ingored, and the TracingPolicy will be loaded in observability mode.

## mmap events

```mmap``` accesses may not generate accurate events. Due to the nature of memory-mapped files we cannot track all accesses. More specifically, a read page-fault will generate a read event. A write to a read-only page will generate a write event. A write page-fault will generate both read and write events proactively. In that case, no kernel intervention happens and thus we cannot track it. 

We may also generate less events compared to the actual accesses. In memory-mapped files, a file is mapped to the virtual address space of a process and accesses are done with CPU ```load```/```store``` instructions. Events will be generated based on page-faults and not  ```load```/```store``` instructions.

By default, Linux does readahead on memory-mapped files to reduce the amount of I/O to the devices. Thus, we will see events due to readahead event without touching these pages.

Calling ```mmap``` with ```MAP_POPULATE``` will immediately generate events based on the flags (i.e. ```PROT_READ``` and ```PROT_WRITE```). In that case, the kernel will create all the required mappings and read actual data from the file. Any further accesses on that mapping will not generate any page faults. In the other cases, it will generate events on demand (i.e. during page faults or readahead).

As memory-mapped files is a very common operation when a new process starts (i.e. map executable and libraries), they may generate a large amount of events if not filtered correctly.

In the case of [enforcement](#enforcement), we block `mmap` calls. This is because we cannot block during page-faults.

## Metrics

FIM also provides [Prometheus](https://prometheus.io/) metrics.

`tetragon_file_total_actions` is a counter per action, k8s namespace, node name, operation, tracing policy name, and rule that matches. An example is:
```
tetragon_file_total_actions{action="FILE_DELETE",namespace="<host>",node="minikube",operation="FILE_OP_BLOCK",",policy="fim-host-block-passwd-shadow",rule="/etc/passwd"} 1
tetragon_file_total_actions{action="FILE_DELETE",namespace="<host>",node="minikube",operation="FILE_OP_BLOCK",policy="fim-host-block-passwd-shadow",rule="/etc/shadow"} 1
tetragon_file_total_actions{action="FILE_DELETE",namespace="ubuntu",node="minikube",operation="FILE_OP_POST",policy="fim-pods-observe-etc-var",rule="/var/"} 3
tetragon_file_total_actions{action="FILE_READ",namespace="<host>",node="minikube",operation="FILE_OP_POST",policy="fim-all-observe-bin",rule="/bin/"} 10574
tetragon_file_total_actions{action="FILE_READ",namespace="<host>",node="minikube",operation="FILE_OP_POST",policy="fim-all-observe-bin",rule="/sbin/"} 170
tetragon_file_total_actions{action="FILE_READ",namespace="ubuntu",node="minikube",operation="FILE_OP_POST",policy="fim-pods-observe-etc-var",rule="/etc/"} 11
tetragon_file_total_actions{action="FILE_READ",namespace="ubuntu",node="minikube",operation="FILE_OP_POST",policy="fim-pods-observe-etc-var",rule="/var/"} 2
tetragon_file_total_actions{action="FILE_READDIR",namespace="default",node="minikube",operation="FILE_OP_POST",policy="fim-pods-observe-etc-var",rule="/etc/"} 4
tetragon_file_total_actions{action="FILE_READDIR",namespace="default",node="minikube",operation="FILE_OP_POST",policy="fim-pods-observe-etc-var",rule="/var/"} 26
tetragon_file_total_actions{action="FILE_WRITE",namespace="<host>",node="minikube",operation="FILE_OP_POST",policy="fim-all-observe-bin",rule="/bin/"} 178
tetragon_file_total_actions{action="FILE_WRITE",namespace="<host>",node="minikube",operation="FILE_OP_POST",policy="fim-all-observe-bin",rule="/sbin/"} 10
```

`tetragon_file_total_events` is a counter for the total number of events that FIM generates. Finally, `tetragon_file_total_errors` shows FIM errors. In normal execution, all errors should be zero.

## Using FIM in OpenShift/RetHat 4.18 kernels

When a user enables FIM, it first checks that the kernel version is >= 4.19. OpenShift/RetHat 4.18 kernels have backported a lot of features provided by newer kernels and these include all functionality needed to run Tetragon's FIM. To bypass this chech and try to load FIM, you should set `file_config.forceLoad` to true. An example is:

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "file-monitoring"
spec:
  file:
    file_config:
      forceLoad: "true"
    file_paths:
    - "/etc/"
    file_paths_exclude:
    - "/etc/locale.alias"
    monitorHostFiles: true
```

## Known Limitations

1. There are cases where errors will cause the operation not to happen, but an event will be emitted. These does not include insufficient permissions, i.e., if an operation is not completed due to insufficient permissions no event is generated.
2. There are some limitations with creating/deleting symlinks after the agent has started:
    - Creating a new symlink (after file monitoring starts) in a watched directory that points to a directory that is not watched.
    - Deleting a symlink will not remove the watched (previously) target file.
3. Renaming directories is racy because we need to scan the hierarchy in user-space. Renaming files do not have this issue.
4. Only path prefixes are supported for matching files.
5. We do not track `mount`/`unmount`/`chroot` operations inside a watched directory (i.e. if we monitor `/etc/` and we mount a new tree at `/etc/test/` we will not get any events from files/directories inside `/etc/test/`).
6. We check for invalid UTF-8 bytes in path names. If we find any, we replace that with "�", which leads to information being lost. We may need to use alterative ways to handle them (i.e. strconv.Quote()) or represent paths with bytes to avoid lost information.
