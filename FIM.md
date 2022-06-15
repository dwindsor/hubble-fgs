# File Integrity Monitoring (FIM)

Hubble-FGS now supports File Integrity Monitoring (FIM). More specifically, it can generate events for file operations based on watch and exclude paths without requiring from the user to provide any complex configurations. 

## How to enable FIM?

To enable FIM the user should use a CRD similar to:

```yaml
apiVersion: isovalent.com/v1alpha1
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

To enable FIM, the user should provide a least one path under ```.spec.file.file_paths```. Field ```.spec.file.file_paths``` include prefixes that the user needs to monitor while ```.spec.file.file_paths_exclude``` includes prefixes that the user wants to exclude (i.e. to reduce the amount of events).

Path filtering is prefix based. This means that the previous CRD will generate events for all file paths that start with ```/etc/``` excluding the prefix ```/etc/demo1```. This will also exclude ```/etc/demo10``` which has the same exclude prefix. Deleting a file and creating that again will not affect the filtering on that.

The user can specify prefixes up to ```256``` characters. Furthermore the sum of ```file_path``` and ```exclude_file_path``` should not exceed ```4096```. 

## Event format

A FIM generated event looks like:

```json
{
  "process_file": {
    "process": {
      "exec_id": "OjE4MjMwMzkxNTI2NDc6MTU3Nzc=",
      "pid": 15777,
      "uid": 0,
      "cwd": "/root",
      "binary": "/usr/bin/cat",
      "arguments": "/etc/passwd",
      "flags": "execve clone",
      "start_time": "2022-06-10T15:24:25.715Z",
      "auid": 1010,
      "parent_exec_id": "OjE3NzY1NjAwMDAwMDA6MTU3NDM=",
      "refcnt": 1
    },
    "parent": {
      "exec_id": "OjE3NzY1NjAwMDAwMDA6MTU3NDM=",
      "pid": 15743,
      "uid": 0,
      "cwd": "/root",
      "binary": "/usr/bin/bash",
      "flags": "procFS auid",
      "start_time": "2022-06-10T15:23:39.235Z",
      "auid": 0,
      "parent_exec_id": "OjE3NzY1NTAwMDAwMDA6MTU3NDI=",
      "refcnt": 2
    },
    "action": "FILE_READ",
    "filename": "/etc/passwd",
    "inode_number": "75716",
    "time": "2022-06-10T15:24:25.716Z",
    "hook": "rw_verify_area"
  },
  "time": "2022-06-10T15:24:25.716Z"
}
```

We defined a new event type ```process_file```. Except from the known ```process```, ```parent```, and ```time``` fields it also includes some new fields. These include:
1. ```action``` is the type of the operations (i.e. ```FILE_READ```/```FILE_WRITE```/```FILE_DELETE```).
2. ```filename``` is the full path of the file.
3. ```inode_number``` is the inode number of the file.
4. ```time``` is the time of the event.
5. ```hook``` is the kernel function that generates the event.

## What does FIM supports?

1. ### ```FILE_READ```/```FILE_WRITE```
    With these events the user can get events for accessing or modifying files. FIM transparently handles almost all(?) different ways to do I/O to files.

    There are CI jobs that ensure that we generate events for the following ways to do I/O:

    1. Using ```read```/```write``` family system calls. These include: ```read```, ```readv```, ```pread64```, ```preadv```, ```preadv2```, ```write```, ```writev```, ```pwrite64```, ```pwritev```, and ```pwritev2``` system calls.
    2. Optmized ways to copy files inside kernel. These include: ```copy_file_range```, ```sendfile```, and ```splice``` system calls.
    3. Asynchronous ways to do I/O. These include [```io_uring```](https://man.archlinux.org/man/io_uring.7.en) and [```aio```](https://man7.org/linux/man-pages/man7/aio.7.html)
    4. File access through memory-mapped files (i.e. ```mmap```). Also check [here](#mmap-events) for details and limitation on generated events.
    5. ```fallocate*``` system calls.

2. ### ```FILE_DELETE```
    With these event the user can get events for deleting files.

    There are CI jobs that ensure that we generate events with ```unlink``` system call.

All of these are continuously tested on 5.4, 5.10, and 5.15 kernels (longterm releases). All ```>= 5.4``` kernels should be supported but not continuously tested.

## mmap events

```mmap``` accesses may not generate accurate events. Due to the nature of memory-mapped files we cannot track all accesses. More specifically, a read page-fault will generate a read event. A write to a read-only page will generate a write event. A write page-fault will generate both read and write events proactively. In that case, no kernel intervention happens and thus we cannot track it. 

We may also generate less events compared to the actual accesses. In memory-mapped files, a file is mapped to the virtual address space of a process and accesses are done with CPU ```load```/```store``` instructions. Events will be generated based on page-faults and not  ```load```/```store``` instructions. 

By default, Linux does readahead on memory-mapped files to reduce the amount of I/O to the devices. Thus, we will see events due to readahead event without touching these pages.

Calling ```mmap``` with ```MAP_POPULATE``` will immediately generate events based on the flags (i.e. ```PROT_READ``` and ```PROT_WRITE```). In that case, the kernel will create all the required mappings and read actual data from the file. Any further accesses on that mapping will not generate any page faults. In the other cases, it will generate events on demand (i.e. during page faults or readahead).

As memory-mapped files is a very common operation when a new process starts (i.e. map executable and libraries), they may generate a large amount of events if not filtered correctly.

## Known Limitations

1. Kernels ```< 5.4``` are not currently supported because of large program sizes. This should be easily fixed with tail calls if needed.
2. We may generate an event for an I/O that will fail (i.e. a write to a full file system). For now we do not track if the actual I/O is successfull or not. We mosty generate events for the 'intention' to access files.
3. Hard and symbolic links are not supported yet. 
4. No support for file hashes yet.
5. Getting events for block devices (instead of regular files) is not supported.
6. Although ```fallocate*``` system calls generate events, ```truncate*``` will not gerate events. Not a limitation to implement, but ```truncate*``` is a metadata operation while ```fallocate*``` is a file system operation.
7. Listing the contents of a directory (i.e. with [readdir](https://man7.org/linux/man-pages/man3/readdir.3.html) or [getdents*](https://man7.org/linux/man-pages/man2/getdents.2.html) system calls) will not generate read events. Not a limitation to implement, but this is a directory (and not a file) operation.
8. Now the CI runs only with a single file system. Maybe create more jobs to cover other commonly used file systems as well.
9. No testing with ```minikube``` yet, but it should work as expected.

