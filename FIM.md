# File Integrity Monitoring (FIM)

Hubble-FGS now supports File Integrity Monitoring (FIM). More specifically, it can generate events for file operations based on watch and exclude paths without requiring from the user to provide any complex configurations. 

***In order to use file monitoring inside K8s, we require the host root (```/```) to be mounted inside ```hubble-enterprise``` pod under ```/hostRoot```. Helm charts will not do that for us. We need to provide the appropriate command-line arguments. An example of these arguments can be found [here](contrib/kind/install-fgs.sh#L97-L101).***

***FIM can be also used in bare-metal hosts outside of K8s.***

## How to enable FIM?

To enable FIM the user should use a CRD similar to:

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "file-monitoring"
spec:
  file:
    file_paths:
    - "/etc/"
    - "/var/testfile"
    file_paths_exclude:
    - "/etc/demo1"
    - "/etc/demo2"
    - "/etc/locale.alias"

```

To enable FIM, the user should provide a least one path under ```spec.file.file_paths```. Field ```spec.file.file_paths``` include prefixes that the user needs to monitor while ```spec.file.file_paths_exclude``` includes prefixes that the user wants to exclude (i.e. to reduce the amount of events).

Path filtering is prefix based. This means that the previous CRD will generate events for all file paths that start with ```/etc/``` excluding the prefix ```/etc/demo1```. This will also exclude ```/etc/demo10``` which has the same exclude prefix. Deleting a file and creating that again will not affect the filtering on that.

The user can specify prefixes up to ```256``` characters. Furthermore, the sum of ```file_path``` and ```exclude_file_path``` should not exceed ```4096```. Finally, the total number of all files that we monitor should not exceed ```128K``` and the total number of all directories that we monitor should not exceed ```128K```. Except from the length of the prefixes, the rest can be easily increased. 

## Event format

A FIM generated event looks like (we omit ```process``` and ```parent``` fields as these are similar to other events):

```json
{
  "process_file": {
    "process": {...},
    "parent": {...},
    "action": "FILE_READ",
    "args": {
      "generic_arg": {
        "file": {
          "filename": "/etc/shadow",
          "inode": {
            "number": "25288789",
            "fs": {
              "name": "overlay",
              "dev": "0:54",
              "id": "overlay",
              "uuid": "00000000-0000-0000-0000-000000000000"
            }
          },
          "parent_inode": {
            "number": "25288733",
            "fs": {
              "name": "overlay",
              "dev": "0:54",
              "id": "overlay",
              "uuid": "00000000-0000-0000-0000-000000000000"
            }
          }
        },
        "io": {
          "offset": "698",
          "size": "131072"
        },
        "mnt_ns": {
          "inum": 4026532574
        }
      }
    },
    "time": "2022-09-26T08:42:23.724452552Z",
    "hook": "rw_verify_area"
  },
  "node_name": "fgs-cli-ci-control-plane",
  "time": "2022-09-26T08:42:23.724449792Z"
}
```

FIM defines ```process_file```, a new event type. Except from the known ```process```, ```parent```, ```time```, and ```node_name``` fields, it also includes some new fields. These include:
1. ```action``` is the type of the operations (i.e. ```FILE_READ```/```FILE_WRITE```/```FILE_DELETE```/```FILE_CREATE```/```FILE_RMDIR```/```FILE_MKDIR```).
2. ```args.generic_arg.file.filename``` is the full path of the file that is related to this event.
3. ```args.generic_arg.file.inode``` the inode number and file system details of the file/directory shown in the ```filename```.
4. ```args.generic_arg.file.parent_inode``` the inode number and file system details of the parent directory (i.e. the directory that contains the file/directory that we care).
5. ```args.generic_arg.file.io``` details of ```FILE_READ```/```FILE_WRITE``` events (empty on other events). The ```offset``` and the ```size``` of the I/O to the file.
6. ```args.generic_arg.file.mnt_ns``` the mnt namespace of the process the time of the event. 
7. ```args.time``` is the time of the event.
8. ```args.hook``` is the kernel function that generates the event (mainly for debugging).

A ```FILE_RENAME``` action exists, but it has a slightly different format. An example is (we omit ```process``` and ```parent``` fields as these are similar to other events):
```json
{
  "process_file": {
    "process": {...},
    "parent": {...},
    "action": "FILE_RENAME",
    "args": {
      "rename_arg": {
        "src": {
          "filename": "/etc/testfile.dat",
          "inode": {
            "number": "1956",
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
          }
        },
        "dst": {
          "filename": "testfile.dat",
          "inode": {},
          "parent_inode": {
            "number": "2",
            "fs": {
              "name": "ext4",
              "dev": "8:1",
              "id": "sda1",
              "uuid": "5b8e9b9c-a139-4214-973c-339a7e39ed55"
            }
          }
        },
        "mnt_ns": {
          "inum": 4026531841,
          "is_host": true
        },
        "flags": [
          "MOVE_OUTSIDE",
          "SRC_REG_FILE",
          "DST_NOT_EXISTS"
        ]
      }
    },
    "time": "2022-09-28T08:32:53.326162026Z",
    "hook": "vfs_rename"
  },
  "time": "2022-09-28T08:32:53.326159039Z"
}
```

This event contains ```rename_arg``` instead of ```generic_arg``` in order to provide details about both the source and destination in the rename operation. More specifically:
1. ```args.rename_arg.src``` is similar to ```args.generic_arg.file``` described in the previous event, but this is related to source file/directory.
2. ```args.rename_arg.dst``` is similar to ```args.generic_arg.file``` described in the previous event, but this is related to destination file/directory.
3. ```args.rename_arg.mnt_ns``` is similar to ```args.generic_arg.file.mnt_ns``` described in the previous event.
4. ```args.rename_arg.flags``` contains details about the rename operation. These flags can be:
    - ```MOVE_INSIDE``` both source and destination file/directory are inside a watched directory.
    - ```MOVE_OUTSIDE``` source file/directory is inside a watched directory but destination is not.
    - ```MOVE_INTERNALLY``` source file/directory is not inside a watched directory but destination is.
    - ```SRC_REG_FILE``` source is a file.
    - ```SRC_DIRECTORY``` source is a directory.
    - ```DST_NOT_EXISTS``` destination name does not exist (will create it).
    - ```DST_REG_FILE``` destination is a file (already exists).
    - ```DST_DIRECTORY``` destination is a directory (already exists).

## What does FIM supports?

1. ### ```FILE_READ```/```FILE_WRITE```
    These are events for accessing or modifying files inside a watched path. Tetragon's FIM implementation, to our knowledge, transparently handles all different ways to file I/O.

    There are CI jobs that ensure that we generate events for the following ways to do I/O:

    1. Using ```read```/```write``` family system calls. These include: ```read```, ```readv```, ```pread64```, ```preadv```, ```preadv2```, ```write```, ```writev```, ```pwrite64```, ```pwritev```, and ```pwritev2``` system calls.
    2. Optimized ways to copy files inside kernel. These include: ```copy_file_range```, ```sendfile```, and ```splice``` system calls.
    3. Asynchronous ways to do I/O. These include [```io_uring```](https://man.archlinux.org/man/io_uring.7.en) and [```aio```](https://man7.org/linux/man-pages/man7/aio.7.html)
    4. File access through memory-mapped files (i.e. ```mmap```). Also check [here](#mmap-events) for details and limitation on generated events.
    5. ```fallocate*``` system calls.

2. ### ```FILE_CREATE```
    These are events for creating files inside a watched path.

3. ### ```FILE_DELETE```
    These are events for deleting files inside a watched path.

4. ### ```FILE_MKDIR```
    These are events for creating directories inside a watched path.

5. ### ```FILE_RMDIR```
    These are events for deleting directories inside a watched path.

6. ### ```FILE_RENAME```
    These are events for renaming (mv) files/directories inside/outside a watched path.

FIM requires a kernel version of 5.4 or later. Our tests cover all above on 5.4, 5.10, and 5.15 kernels (longterm releases).

## mmap events

```mmap``` accesses may not generate accurate events. Due to the nature of memory-mapped files we cannot track all accesses. More specifically, a read page-fault will generate a read event. A write to a read-only page will generate a write event. A write page-fault will generate both read and write events proactively. In that case, no kernel intervention happens and thus we cannot track it. 

We may also generate less events compared to the actual accesses. In memory-mapped files, a file is mapped to the virtual address space of a process and accesses are done with CPU ```load```/```store``` instructions. Events will be generated based on page-faults and not  ```load```/```store``` instructions. 

By default, Linux does readahead on memory-mapped files to reduce the amount of I/O to the devices. Thus, we will see events due to readahead event without touching these pages.

Calling ```mmap``` with ```MAP_POPULATE``` will immediately generate events based on the flags (i.e. ```PROT_READ``` and ```PROT_WRITE```). In that case, the kernel will create all the required mappings and read actual data from the file. Any further accesses on that mapping will not generate any page faults. In the other cases, it will generate events on demand (i.e. during page faults or readahead).

As memory-mapped files is a very common operation when a new process starts (i.e. map executable and libraries), they may generate a large amount of events if not filtered correctly.

## Known Limitations

1. There are cases where errors will cause the operation not to happen, but an event will be emitted. These does not include insufficient permissions, i.e., if an operation is not completed due to insufficient permissions no event is generated.
2. Additional filtering using selectors (e.g., matchNamespaces) is not supported.
3. There are some limitations with creating/deleting symlinks after the agent has started
    - Creating a new symlink (after file monitoring starts) in a watched directory that points to a directory that is not watched.
    - Deleting a symlink will not remove the watched (previously) target file.
4. Renaming directories is racy because we need to scan the hierarchy in user-space.
5. Enforcement (e..g, killing a process when trying to access files) is not currently supported.
6. Only path prefixes are supported for matching files.
7. We do not track mount/unmount inside/outside of watched directory (i.e. if we monitor ```/etc``` and we mount a new tree at ```/etc/test/``` we will not get any events from ```/etc/test/```).
8. There is no way to monitor files inside a K8s Pod (we only monitor files in the host).
9. Kernels ```< 5.4``` are not currently supported.
10. Calling truncate to shrink or extend the size of a file to the specified size will not generate any events.
