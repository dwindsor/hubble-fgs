# Protocol Documentation
<a name="top"></a>

## Table of Contents

- [application_model/v1alpha/syscalls.proto](#application_model_v1alpha_syscalls-proto)
    - [Abi](#application_model-v1alpha-Abi)
    - [Sys](#application_model-v1alpha-Sys)
  
- [application_model/v1alpha/application_model.proto](#application_model_v1alpha_application_model-proto)
    - [ApplicationConnection](#application_model-v1alpha-ApplicationConnection)
    - [ApplicationContainer](#application_model-v1alpha-ApplicationContainer)
    - [ApplicationHost](#application_model-v1alpha-ApplicationHost)
    - [ApplicationModel](#application_model-v1alpha-ApplicationModel)
    - [ApplicationModelEvent](#application_model-v1alpha-ApplicationModelEvent)
    - [ApplicationModelEvent.NodeLabelsEntry](#application_model-v1alpha-ApplicationModelEvent-NodeLabelsEntry)
    - [ApplicationModelFragment](#application_model-v1alpha-ApplicationModelFragment)
    - [ApplicationModelFragment.NodeLabelsEntry](#application_model-v1alpha-ApplicationModelFragment-NodeLabelsEntry)
    - [ApplicationNamespace](#application_model-v1alpha-ApplicationNamespace)
    - [ApplicationProcessGroup](#application_model-v1alpha-ApplicationProcessGroup)
    - [ApplicationSyscalls](#application_model-v1alpha-ApplicationSyscalls)
    - [ApplicationWorkload](#application_model-v1alpha-ApplicationWorkload)
    - [ConnectionStats](#application_model-v1alpha-ConnectionStats)
    - [Destination](#application_model-v1alpha-Destination)
    - [DestinationDns](#application_model-v1alpha-DestinationDns)
    - [DestinationIP](#application_model-v1alpha-DestinationIP)
    - [DestinationWorkload](#application_model-v1alpha-DestinationWorkload)
    - [GetModelRequest](#application_model-v1alpha-GetModelRequest)
    - [GetModelResponse](#application_model-v1alpha-GetModelResponse)
    - [NetworkConnectTelemetry](#application_model-v1alpha-NetworkConnectTelemetry)
    - [NetworkConnectTelemetry.NodeLabelsEntry](#application_model-v1alpha-NetworkConnectTelemetry-NodeLabelsEntry)
    - [NetworkPolicy](#application_model-v1alpha-NetworkPolicy)
    - [ProcessTelemetry](#application_model-v1alpha-ProcessTelemetry)
    - [ProcessTelemetry.NodeLabelsEntry](#application_model-v1alpha-ProcessTelemetry-NodeLabelsEntry)
    - [StreamModelFragmentsRequest](#application_model-v1alpha-StreamModelFragmentsRequest)
    - [StreamModelFragmentsResponse](#application_model-v1alpha-StreamModelFragmentsResponse)
    - [StreamModelRequest](#application_model-v1alpha-StreamModelRequest)
    - [StreamModelResponse](#application_model-v1alpha-StreamModelResponse)
    - [StreamTelemetryRequest](#application_model-v1alpha-StreamTelemetryRequest)
    - [StreamTelemetryResponse](#application_model-v1alpha-StreamTelemetryResponse)
  
    - [DestinationType](#application_model-v1alpha-DestinationType)
    - [ObservationPoint](#application_model-v1alpha-ObservationPoint)
    - [PolicyVerdict](#application_model-v1alpha-PolicyVerdict)
    - [TelemetryType](#application_model-v1alpha-TelemetryType)
  
    - [ApplicationModelService](#application_model-v1alpha-ApplicationModelService)
  
- [Scalar Value Types](#scalar-value-types)



<a name="application_model_v1alpha_syscalls-proto"></a>
<p align="right"><a href="#top">Top</a></p>

## application_model/v1alpha/syscalls.proto


 


<a name="application_model-v1alpha-Abi"></a>

### Abi


| Name | Number | Description |
| ---- | ------ | ----------- |
| ABI_UNSPECIFIED | 0 |  |
| ABI_X86_64 | 1 |  |
| ABI_I386 | 2 |  |
| ABI_ARM64 | 3 |  |
| ABI_ARM32 | 4 |  |



<a name="application_model-v1alpha-Sys"></a>

### Sys
Syscalls is a list of system calls in the Linux kernel, in no particular order.
WARNING for consumers: numbers are arbitrary.

| Name | Number | Description |
| ---- | ------ | ----------- |
| SYS_UNSPECIFIED | 0 |  |
| SYS_READ | 1 |  |
| SYS_WRITE | 2 |  |
| SYS_OPEN | 3 |  |
| SYS_CLOSE | 4 |  |
| SYS_STAT | 5 |  |
| SYS_FSTAT | 6 |  |
| SYS_LSTAT | 7 |  |
| SYS_POLL | 8 |  |
| SYS_LSEEK | 9 |  |
| SYS_MMAP | 10 |  |
| SYS_MPROTECT | 11 |  |
| SYS_MUNMAP | 12 |  |
| SYS_BRK | 13 |  |
| SYS_RT_SIGACTION | 14 |  |
| SYS_RT_SIGPROCMASK | 15 |  |
| SYS_RT_SIGRETURN | 16 |  |
| SYS_IOCTL | 17 |  |
| SYS_PREAD64 | 18 |  |
| SYS_PWRITE64 | 19 |  |
| SYS_READV | 20 |  |
| SYS_WRITEV | 21 |  |
| SYS_ACCESS | 22 |  |
| SYS_PIPE | 23 |  |
| SYS_SELECT | 24 |  |
| SYS_SCHED_YIELD | 25 |  |
| SYS_MREMAP | 26 |  |
| SYS_MSYNC | 27 |  |
| SYS_MINCORE | 28 |  |
| SYS_MADVISE | 29 |  |
| SYS_SHMGET | 30 |  |
| SYS_SHMAT | 31 |  |
| SYS_SHMCTL | 32 |  |
| SYS_DUP | 33 |  |
| SYS_DUP2 | 34 |  |
| SYS_PAUSE | 35 |  |
| SYS_NANOSLEEP | 36 |  |
| SYS_GETITIMER | 37 |  |
| SYS_ALARM | 38 |  |
| SYS_SETITIMER | 39 |  |
| SYS_GETPID | 40 |  |
| SYS_SENDFILE | 41 |  |
| SYS_SOCKET | 42 |  |
| SYS_CONNECT | 43 |  |
| SYS_ACCEPT | 44 |  |
| SYS_SENDTO | 45 |  |
| SYS_RECVFROM | 46 |  |
| SYS_SENDMSG | 47 |  |
| SYS_RECVMSG | 48 |  |
| SYS_SHUTDOWN | 49 |  |
| SYS_BIND | 50 |  |
| SYS_LISTEN | 51 |  |
| SYS_GETSOCKNAME | 52 |  |
| SYS_GETPEERNAME | 53 |  |
| SYS_SOCKETPAIR | 54 |  |
| SYS_SETSOCKOPT | 55 |  |
| SYS_GETSOCKOPT | 56 |  |
| SYS_CLONE | 57 |  |
| SYS_FORK | 58 |  |
| SYS_VFORK | 59 |  |
| SYS_EXECVE | 60 |  |
| SYS_EXIT | 61 |  |
| SYS_WAIT4 | 62 |  |
| SYS_KILL | 63 |  |
| SYS_UNAME | 64 |  |
| SYS_SEMGET | 65 |  |
| SYS_SEMOP | 66 |  |
| SYS_SEMCTL | 67 |  |
| SYS_SHMDT | 68 |  |
| SYS_MSGGET | 69 |  |
| SYS_MSGSND | 70 |  |
| SYS_MSGRCV | 71 |  |
| SYS_MSGCTL | 72 |  |
| SYS_FCNTL | 73 |  |
| SYS_FLOCK | 74 |  |
| SYS_FSYNC | 75 |  |
| SYS_FDATASYNC | 76 |  |
| SYS_TRUNCATE | 77 |  |
| SYS_FTRUNCATE | 78 |  |
| SYS_GETDENTS | 79 |  |
| SYS_GETCWD | 80 |  |
| SYS_CHDIR | 81 |  |
| SYS_FCHDIR | 82 |  |
| SYS_RENAME | 83 |  |
| SYS_MKDIR | 84 |  |
| SYS_RMDIR | 85 |  |
| SYS_CREAT | 86 |  |
| SYS_LINK | 87 |  |
| SYS_UNLINK | 88 |  |
| SYS_SYMLINK | 89 |  |
| SYS_READLINK | 90 |  |
| SYS_CHMOD | 91 |  |
| SYS_FCHMOD | 92 |  |
| SYS_CHOWN | 93 |  |
| SYS_FCHOWN | 94 |  |
| SYS_LCHOWN | 95 |  |
| SYS_UMASK | 96 |  |
| SYS_GETTIMEOFDAY | 97 |  |
| SYS_GETRLIMIT | 98 |  |
| SYS_GETRUSAGE | 99 |  |
| SYS_SYSINFO | 100 |  |
| SYS_TIMES | 101 |  |
| SYS_PTRACE | 102 |  |
| SYS_GETUID | 103 |  |
| SYS_SYSLOG | 104 |  |
| SYS_GETGID | 105 |  |
| SYS_SETUID | 106 |  |
| SYS_SETGID | 107 |  |
| SYS_GETEUID | 108 |  |
| SYS_GETEGID | 109 |  |
| SYS_SETPGID | 110 |  |
| SYS_GETPPID | 111 |  |
| SYS_GETPGRP | 112 |  |
| SYS_SETSID | 113 |  |
| SYS_SETREUID | 114 |  |
| SYS_SETREGID | 115 |  |
| SYS_GETGROUPS | 116 |  |
| SYS_SETGROUPS | 117 |  |
| SYS_SETRESUID | 118 |  |
| SYS_GETRESUID | 119 |  |
| SYS_SETRESGID | 120 |  |
| SYS_GETRESGID | 121 |  |
| SYS_GETPGID | 122 |  |
| SYS_SETFSUID | 123 |  |
| SYS_SETFSGID | 124 |  |
| SYS_GETSID | 125 |  |
| SYS_CAPGET | 126 |  |
| SYS_CAPSET | 127 |  |
| SYS_RT_SIGPENDING | 128 |  |
| SYS_RT_SIGTIMEDWAIT | 129 |  |
| SYS_RT_SIGQUEUEINFO | 130 |  |
| SYS_RT_SIGSUSPEND | 131 |  |
| SYS_SIGALTSTACK | 132 |  |
| SYS_UTIME | 133 |  |
| SYS_MKNOD | 134 |  |
| SYS_USELIB | 135 |  |
| SYS_PERSONALITY | 136 |  |
| SYS_USTAT | 137 |  |
| SYS_STATFS | 138 |  |
| SYS_FSTATFS | 139 |  |
| SYS_SYSFS | 140 |  |
| SYS_GETPRIORITY | 141 |  |
| SYS_SETPRIORITY | 142 |  |
| SYS_SCHED_SETPARAM | 143 |  |
| SYS_SCHED_GETPARAM | 144 |  |
| SYS_SCHED_SETSCHEDULER | 145 |  |
| SYS_SCHED_GETSCHEDULER | 146 |  |
| SYS_SCHED_GET_PRIORITY_MAX | 147 |  |
| SYS_SCHED_GET_PRIORITY_MIN | 148 |  |
| SYS_SCHED_RR_GET_INTERVAL | 149 |  |
| SYS_MLOCK | 150 |  |
| SYS_MUNLOCK | 151 |  |
| SYS_MLOCKALL | 152 |  |
| SYS_MUNLOCKALL | 153 |  |
| SYS_VHANGUP | 154 |  |
| SYS_MODIFY_LDT | 155 |  |
| SYS_PIVOT_ROOT | 156 |  |
| SYS_SYSCTL | 157 |  |
| SYS_PRCTL | 158 |  |
| SYS_ARCH_PRCTL | 159 |  |
| SYS_ADJTIMEX | 160 |  |
| SYS_SETRLIMIT | 161 |  |
| SYS_CHROOT | 162 |  |
| SYS_SYNC | 163 |  |
| SYS_ACCT | 164 |  |
| SYS_SETTIMEOFDAY | 165 |  |
| SYS_MOUNT | 166 |  |
| SYS_UMOUNT2 | 167 |  |
| SYS_SWAPON | 168 |  |
| SYS_SWAPOFF | 169 |  |
| SYS_REBOOT | 170 |  |
| SYS_SETHOSTNAME | 171 |  |
| SYS_SETDOMAINNAME | 172 |  |
| SYS_IOPL | 173 |  |
| SYS_IOPERM | 174 |  |
| SYS_CREATE_MODULE | 175 |  |
| SYS_INIT_MODULE | 176 |  |
| SYS_DELETE_MODULE | 177 |  |
| SYS_GET_KERNEL_SYMS | 178 |  |
| SYS_QUERY_MODULE | 179 |  |
| SYS_QUOTACTL | 180 |  |
| SYS_NFSSERVCTL | 181 |  |
| SYS_GETPMSG | 182 |  |
| SYS_PUTPMSG | 183 |  |
| SYS_AFS_SYSCALL | 184 |  |
| SYS_TUXCALL | 185 |  |
| SYS_SECURITY | 186 |  |
| SYS_GETTID | 187 |  |
| SYS_READAHEAD | 188 |  |
| SYS_SETXATTR | 189 |  |
| SYS_LSETXATTR | 190 |  |
| SYS_FSETXATTR | 191 |  |
| SYS_GETXATTR | 192 |  |
| SYS_LGETXATTR | 193 |  |
| SYS_FGETXATTR | 194 |  |
| SYS_LISTXATTR | 195 |  |
| SYS_LLISTXATTR | 196 |  |
| SYS_FLISTXATTR | 197 |  |
| SYS_REMOVEXATTR | 198 |  |
| SYS_LREMOVEXATTR | 199 |  |
| SYS_FREMOVEXATTR | 200 |  |
| SYS_TKILL | 201 |  |
| SYS_TIME | 202 |  |
| SYS_FUTEX | 203 |  |
| SYS_SCHED_SETAFFINITY | 204 |  |
| SYS_SCHED_GETAFFINITY | 205 |  |
| SYS_SET_THREAD_AREA | 206 |  |
| SYS_IO_SETUP | 207 |  |
| SYS_IO_DESTROY | 208 |  |
| SYS_IO_GETEVENTS | 209 |  |
| SYS_IO_SUBMIT | 210 |  |
| SYS_IO_CANCEL | 211 |  |
| SYS_GET_THREAD_AREA | 212 |  |
| SYS_LOOKUP_DCOOKIE | 213 |  |
| SYS_EPOLL_CREATE | 214 |  |
| SYS_EPOLL_CTL_OLD | 215 |  |
| SYS_EPOLL_WAIT_OLD | 216 |  |
| SYS_REMAP_FILE_PAGES | 217 |  |
| SYS_GETDENTS64 | 218 |  |
| SYS_SET_TID_ADDRESS | 219 |  |
| SYS_RESTART_SYSCALL | 220 |  |
| SYS_SEMTIMEDOP | 221 |  |
| SYS_FADVISE64 | 222 |  |
| SYS_TIMER_CREATE | 223 |  |
| SYS_TIMER_SETTIME | 224 |  |
| SYS_TIMER_GETTIME | 225 |  |
| SYS_TIMER_GETOVERRUN | 226 |  |
| SYS_TIMER_DELETE | 227 |  |
| SYS_CLOCK_SETTIME | 228 |  |
| SYS_CLOCK_GETTIME | 229 |  |
| SYS_CLOCK_GETRES | 230 |  |
| SYS_CLOCK_NANOSLEEP | 231 |  |
| SYS_EXIT_GROUP | 232 |  |
| SYS_EPOLL_WAIT | 233 |  |
| SYS_EPOLL_CTL | 234 |  |
| SYS_TGKILL | 235 |  |
| SYS_UTIMES | 236 |  |
| SYS_VSERVER | 237 |  |
| SYS_MBIND | 238 |  |
| SYS_SET_MEMPOLICY | 239 |  |
| SYS_GET_MEMPOLICY | 240 |  |
| SYS_MQ_OPEN | 241 |  |
| SYS_MQ_UNLINK | 242 |  |
| SYS_MQ_TIMEDSEND | 243 |  |
| SYS_MQ_TIMEDRECEIVE | 244 |  |
| SYS_MQ_NOTIFY | 245 |  |
| SYS_MQ_GETSETATTR | 246 |  |
| SYS_KEXEC_LOAD | 247 |  |
| SYS_WAITID | 248 |  |
| SYS_ADD_KEY | 249 |  |
| SYS_REQUEST_KEY | 250 |  |
| SYS_KEYCTL | 251 |  |
| SYS_IOPRIO_SET | 252 |  |
| SYS_IOPRIO_GET | 253 |  |
| SYS_INOTIFY_INIT | 254 |  |
| SYS_INOTIFY_ADD_WATCH | 255 |  |
| SYS_INOTIFY_RM_WATCH | 256 |  |
| SYS_MIGRATE_PAGES | 257 |  |
| SYS_OPENAT | 258 |  |
| SYS_MKDIRAT | 259 |  |
| SYS_MKNODAT | 260 |  |
| SYS_FCHOWNAT | 261 |  |
| SYS_FUTIMESAT | 262 |  |
| SYS_NEWFSTATAT | 263 |  |
| SYS_UNLINKAT | 264 |  |
| SYS_RENAMEAT | 265 |  |
| SYS_LINKAT | 266 |  |
| SYS_SYMLINKAT | 267 |  |
| SYS_READLINKAT | 268 |  |
| SYS_FCHMODAT | 269 |  |
| SYS_FACCESSAT | 270 |  |
| SYS_PSELECT6 | 271 |  |
| SYS_PPOLL | 272 |  |
| SYS_UNSHARE | 273 |  |
| SYS_SET_ROBUST_LIST | 274 |  |
| SYS_GET_ROBUST_LIST | 275 |  |
| SYS_SPLICE | 276 |  |
| SYS_TEE | 277 |  |
| SYS_SYNC_FILE_RANGE | 278 |  |
| SYS_VMSPLICE | 279 |  |
| SYS_MOVE_PAGES | 280 |  |
| SYS_UTIMENSAT | 281 |  |
| SYS_EPOLL_PWAIT | 282 |  |
| SYS_SIGNALFD | 283 |  |
| SYS_TIMERFD_CREATE | 284 |  |
| SYS_EVENTFD | 285 |  |
| SYS_FALLOCATE | 286 |  |
| SYS_TIMERFD_SETTIME | 287 |  |
| SYS_TIMERFD_GETTIME | 288 |  |
| SYS_ACCEPT4 | 289 |  |
| SYS_SIGNALFD4 | 290 |  |
| SYS_EVENTFD2 | 291 |  |
| SYS_EPOLL_CREATE1 | 292 |  |
| SYS_DUP3 | 293 |  |
| SYS_PIPE2 | 294 |  |
| SYS_INOTIFY_INIT1 | 295 |  |
| SYS_PREADV | 296 |  |
| SYS_PWRITEV | 297 |  |
| SYS_RT_TGSIGQUEUEINFO | 298 |  |
| SYS_PERF_EVENT_OPEN | 299 |  |
| SYS_RECVMMSG | 300 |  |
| SYS_FANOTIFY_INIT | 301 |  |
| SYS_FANOTIFY_MARK | 302 |  |
| SYS_PRLIMIT64 | 303 |  |
| SYS_NAME_TO_HANDLE_AT | 304 |  |
| SYS_OPEN_BY_HANDLE_AT | 305 |  |
| SYS_CLOCK_ADJTIME | 306 |  |
| SYS_SYNCFS | 307 |  |
| SYS_SENDMMSG | 308 |  |
| SYS_SETNS | 309 |  |
| SYS_GETCPU | 310 |  |
| SYS_PROCESS_VM_READV | 311 |  |
| SYS_PROCESS_VM_WRITEV | 312 |  |
| SYS_KCMP | 313 |  |
| SYS_FINIT_MODULE | 314 |  |
| SYS_SCHED_SETATTR | 315 |  |
| SYS_SCHED_GETATTR | 316 |  |
| SYS_RENAMEAT2 | 317 |  |
| SYS_SECCOMP | 318 |  |
| SYS_GETRANDOM | 319 |  |
| SYS_MEMFD_CREATE | 320 |  |
| SYS_KEXEC_FILE_LOAD | 321 |  |
| SYS_BPF | 322 |  |
| SYS_EXECVEAT | 323 |  |
| SYS_USERFAULTFD | 324 |  |
| SYS_MEMBARRIER | 325 |  |
| SYS_MLOCK2 | 326 |  |
| SYS_COPY_FILE_RANGE | 327 |  |
| SYS_PREADV2 | 328 |  |
| SYS_PWRITEV2 | 329 |  |
| SYS_PKEY_MPROTECT | 330 |  |
| SYS_PKEY_ALLOC | 331 |  |
| SYS_PKEY_FREE | 332 |  |
| SYS_STATX | 333 |  |
| SYS_IO_PGETEVENTS | 334 |  |
| SYS_RSEQ | 335 |  |
| SYS_URETPROBE | 336 |  |
| SYS_PIDFD_SEND_SIGNAL | 337 |  |
| SYS_IO_URING_SETUP | 338 |  |
| SYS_IO_URING_ENTER | 339 |  |
| SYS_IO_URING_REGISTER | 340 |  |
| SYS_OPEN_TREE | 341 |  |
| SYS_MOVE_MOUNT | 342 |  |
| SYS_FSOPEN | 343 |  |
| SYS_FSCONFIG | 344 |  |
| SYS_FSMOUNT | 345 |  |
| SYS_FSPICK | 346 |  |
| SYS_PIDFD_OPEN | 347 |  |
| SYS_CLONE3 | 348 |  |
| SYS_CLOSE_RANGE | 349 |  |
| SYS_OPENAT2 | 350 |  |
| SYS_PIDFD_GETFD | 351 |  |
| SYS_FACCESSAT2 | 352 |  |
| SYS_PROCESS_MADVISE | 353 |  |
| SYS_EPOLL_PWAIT2 | 354 |  |
| SYS_MOUNT_SETATTR | 355 |  |
| SYS_QUOTACTL_FD | 356 |  |
| SYS_LANDLOCK_CREATE_RULESET | 357 |  |
| SYS_LANDLOCK_ADD_RULE | 358 |  |
| SYS_LANDLOCK_RESTRICT_SELF | 359 |  |
| SYS_MEMFD_SECRET | 360 |  |
| SYS_PROCESS_MRELEASE | 361 |  |
| SYS_FUTEX_WAITV | 362 |  |
| SYS_SET_MEMPOLICY_HOME_NODE | 363 |  |
| SYS_CACHESTAT | 364 |  |
| SYS_FCHMODAT2 | 365 |  |
| SYS_MAP_SHADOW_STACK | 366 |  |
| SYS_FUTEX_WAKE | 367 |  |
| SYS_FUTEX_WAIT | 368 |  |
| SYS_FUTEX_REQUEUE | 369 |  |
| SYS_STATMOUNT | 370 |  |
| SYS_LISTMOUNT | 371 |  |
| SYS_LSM_GET_SELF_ATTR | 372 |  |
| SYS_LSM_SET_SELF_ATTR | 373 |  |
| SYS_LSM_LIST_MODULES | 374 |  |
| SYS_MSEAL | 375 |  |
| SYS_WAITPID | 376 |  |
| SYS_BREAK | 377 |  |
| SYS_OLDSTAT | 378 |  |
| SYS_UMOUNT | 379 |  |
| SYS_STIME | 380 |  |
| SYS_OLDFSTAT | 381 |  |
| SYS_STTY | 382 |  |
| SYS_GTTY | 383 |  |
| SYS_NICE | 384 |  |
| SYS_FTIME | 385 |  |
| SYS_PROF | 386 |  |
| SYS_SIGNAL | 387 |  |
| SYS_LOCK | 388 |  |
| SYS_MPX | 389 |  |
| SYS_ULIMIT | 390 |  |
| SYS_OLDOLDUNAME | 391 |  |
| SYS_SIGACTION | 392 |  |
| SYS_SGETMASK | 393 |  |
| SYS_SSETMASK | 394 |  |
| SYS_SIGSUSPEND | 395 |  |
| SYS_SIGPENDING | 396 |  |
| SYS_OLDLSTAT | 397 |  |
| SYS_READDIR | 398 |  |
| SYS_PROFIL | 399 |  |
| SYS_SOCKETCALL | 400 |  |
| SYS_OLDUNAME | 401 |  |
| SYS_IDLE | 402 |  |
| SYS_VM86OLD | 403 |  |
| SYS_IPC | 404 |  |
| SYS_SIGRETURN | 405 |  |
| SYS_SIGPROCMASK | 406 |  |
| SYS_BDFLUSH | 407 |  |
| SYS_LLSEEK | 408 |  |
| SYS_NEWSELECT | 409 |  |
| SYS_VM86 | 410 |  |
| SYS_UGETRLIMIT | 411 |  |
| SYS_MMAP2 | 412 |  |
| SYS_TRUNCATE64 | 413 |  |
| SYS_FTRUNCATE64 | 414 |  |
| SYS_STAT64 | 415 |  |
| SYS_LSTAT64 | 416 |  |
| SYS_FSTAT64 | 417 |  |
| SYS_LCHOWN32 | 418 |  |
| SYS_GETUID32 | 419 |  |
| SYS_GETGID32 | 420 |  |
| SYS_GETEUID32 | 421 |  |
| SYS_GETEGID32 | 422 |  |
| SYS_SETREUID32 | 423 |  |
| SYS_SETREGID32 | 424 |  |
| SYS_GETGROUPS32 | 425 |  |
| SYS_SETGROUPS32 | 426 |  |
| SYS_FCHOWN32 | 427 |  |
| SYS_SETRESUID32 | 428 |  |
| SYS_GETRESUID32 | 429 |  |
| SYS_SETRESGID32 | 430 |  |
| SYS_GETRESGID32 | 431 |  |
| SYS_CHOWN32 | 432 |  |
| SYS_SETUID32 | 433 |  |
| SYS_SETGID32 | 434 |  |
| SYS_SETFSUID32 | 435 |  |
| SYS_SETFSGID32 | 436 |  |
| SYS_FCNTL64 | 437 |  |
| SYS_SENDFILE64 | 438 |  |
| SYS_STATFS64 | 439 |  |
| SYS_FSTATFS64 | 440 |  |
| SYS_FADVISE64_64 | 441 |  |
| SYS_FSTATAT64 | 442 |  |
| SYS_CLOCK_GETTIME64 | 443 |  |
| SYS_CLOCK_SETTIME64 | 444 |  |
| SYS_CLOCK_ADJTIME64 | 445 |  |
| SYS_CLOCK_GETRES_TIME64 | 446 |  |
| SYS_CLOCK_NANOSLEEP_TIME64 | 447 |  |
| SYS_TIMER_GETTIME64 | 448 |  |
| SYS_TIMER_SETTIME64 | 449 |  |
| SYS_TIMERFD_GETTIME64 | 450 |  |
| SYS_TIMERFD_SETTIME64 | 451 |  |
| SYS_UTIMENSAT_TIME64 | 452 |  |
| SYS_PSELECT6_TIME64 | 453 |  |
| SYS_PPOLL_TIME64 | 454 |  |
| SYS_IO_PGETEVENTS_TIME64 | 455 |  |
| SYS_RECVMMSG_TIME64 | 456 |  |
| SYS_MQ_TIMEDSEND_TIME64 | 457 |  |
| SYS_MQ_TIMEDRECEIVE_TIME64 | 458 |  |
| SYS_SEMTIMEDOP_TIME64 | 459 |  |
| SYS_RT_SIGTIMEDWAIT_TIME64 | 460 |  |
| SYS_FUTEX_TIME64 | 461 |  |
| SYS_SCHED_RR_GET_INTERVAL_TIME64 | 462 |  |
| SYS_ARM_FADVISE64_64 | 463 |  |
| SYS_PCICONFIG_IOBASE | 464 |  |
| SYS_PCICONFIG_READ | 465 |  |
| SYS_PCICONFIG_WRITE | 466 |  |
| SYS_SEND | 467 |  |
| SYS_RECV | 468 |  |
| SYS_SYNC_FILE_RANGE2 | 469 |  |
| SYS_CACHEFLUSH | 470 |  |
| SYS_SET_TLS | 471 |  |


 

 

 



<a name="application_model_v1alpha_application_model-proto"></a>
<p align="right"><a href="#top">Top</a></p>

## application_model/v1alpha/application_model.proto



<a name="application_model-v1alpha-ApplicationConnection"></a>

### ApplicationConnection



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| destination | [Destination](#application_model-v1alpha-Destination) |  | Destination information associated with the connection |
| stats | [ConnectionStats](#application_model-v1alpha-ConnectionStats) |  | Statistics associated with the connection |
| policy | [NetworkPolicy](#application_model-v1alpha-NetworkPolicy) |  | Policy information associated with the connection |
| protocol | [common.net.v1alpha.IPProtocol](#common-net-v1alpha-IPProtocol) |  | Network protocol of the connection at the L3/L4 layer. |
| observation_point | [ObservationPoint](#application_model-v1alpha-ObservationPoint) |  | Side of the connection from which the observer saw the connection. |






<a name="application_model-v1alpha-ApplicationContainer"></a>

### ApplicationContainer



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| id | [string](#string) |  | Identifier of the container. |
| name | [string](#string) |  | Name of the container. |
| image | [string](#string) |  | Image of the container. |
| processes | [ApplicationProcessGroup](#application_model-v1alpha-ApplicationProcessGroup) | repeated | A list of process groups in this container. See ApplicationProcessGroup for the definition of a process group. |






<a name="application_model-v1alpha-ApplicationHost"></a>

### ApplicationHost



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| processes | [ApplicationProcessGroup](#application_model-v1alpha-ApplicationProcessGroup) | repeated | A list of process groups in the host namespace. See ApplicationProcessGroup for the definition of a process group. |






<a name="application_model-v1alpha-ApplicationModel"></a>

### ApplicationModel



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| namespaces | [ApplicationNamespace](#application_model-v1alpha-ApplicationNamespace) | repeated |  |
| host | [ApplicationHost](#application_model-v1alpha-ApplicationHost) |  |  |
| id | [string](#string) |  | An opaque ID that uniquely identifies this application model. |






<a name="application_model-v1alpha-ApplicationModelEvent"></a>

### ApplicationModelEvent



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| cluster_name | [string](#string) |  |  |
| node_name | [string](#string) |  |  |
| time | [google.protobuf.Timestamp](#google-protobuf-Timestamp) |  |  |
| application_model | [ApplicationModel](#application_model-v1alpha-ApplicationModel) |  |  |
| node_labels | [ApplicationModelEvent.NodeLabelsEntry](#application_model-v1alpha-ApplicationModelEvent-NodeLabelsEntry) | repeated | Labels of the node that transmitted this application model message. For nodes that belong to a Kubernetes cluster, this field contains Kubernetes node labels. For cloud provider VMs (e.g. AWS, GCP, Azure) that do not belong to any Kubernetes cluster, this field may contain VM tags / labels. |






<a name="application_model-v1alpha-ApplicationModelEvent-NodeLabelsEntry"></a>

### ApplicationModelEvent.NodeLabelsEntry



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| key | [string](#string) |  |  |
| value | [string](#string) |  |  |






<a name="application_model-v1alpha-ApplicationModelFragment"></a>

### ApplicationModelFragment



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| cluster_name | [string](#string) |  |  |
| node_name | [string](#string) |  |  |
| time | [google.protobuf.Timestamp](#google-protobuf-Timestamp) |  |  |
| application_model_fragment | [ApplicationModel](#application_model-v1alpha-ApplicationModel) |  |  |
| fragment_total | [uint64](#uint64) |  | The number of fragments that that comprise the application model. All fragments will have the same application_model.id value. |
| fragment_index | [uint64](#uint64) |  | The index into the the total number of fragments. The first value has fragment_index = 1. |
| node_labels | [ApplicationModelFragment.NodeLabelsEntry](#application_model-v1alpha-ApplicationModelFragment-NodeLabelsEntry) | repeated | Labels of the node that transmitted this application model message. For nodes that belong to a Kubernetes cluster, this field contains Kubernetes node labels. For cloud provider VMs (e.g. AWS, GCP, Azure) that do not belong to any Kubernetes cluster, this field may contain VM tags / labels. |






<a name="application_model-v1alpha-ApplicationModelFragment-NodeLabelsEntry"></a>

### ApplicationModelFragment.NodeLabelsEntry



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| key | [string](#string) |  |  |
| value | [string](#string) |  |  |






<a name="application_model-v1alpha-ApplicationNamespace"></a>

### ApplicationNamespace



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| name | [string](#string) |  |  |
| workloads | [ApplicationWorkload](#application_model-v1alpha-ApplicationWorkload) | repeated |  |






<a name="application_model-v1alpha-ApplicationProcessGroup"></a>

### ApplicationProcessGroup
ApplicationProcessGroup represents a set of processes that are grouped by
the following criteria:

- They got spawned by processes that belong to a same process group.
- They have the same command name.
- They have the same command line arguments.
- For processes running in a Kubernetes workload, they belong to the same
  Kubernetes workload.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| hash | [string](#string) |  | Hash to identify this process group in the process group tree. |
| name | [string](#string) |  |  |
| arguments | [string](#string) |  | Arguments passed to this process. |
| children | [ApplicationProcessGroup](#application_model-v1alpha-ApplicationProcessGroup) | repeated | Child process groups of this process. |
| connections | [ApplicationConnection](#application_model-v1alpha-ApplicationConnection) | repeated |  |
| in_init_tree | [google.protobuf.BoolValue](#google-protobuf-BoolValue) |  | Indicates if this process is containerized and is a member of the process tree rooted at pid=1 in its PID namespace. |
| syscall_info | [ApplicationSyscalls](#application_model-v1alpha-ApplicationSyscalls) |  | System calls used by this process and their ABI. |
| process_count | [uint64](#uint64) |  | Number of processes that are currently running in this process group. Implementations of this API may remove the process group from the application model if this count and the counts of all the descendant process groups are zero. |
| latest_start_time | [google.protobuf.Timestamp](#google-protobuf-Timestamp) |  | The latest time at which a process in this process group was observed to start. |
| latest_exit_time | [google.protobuf.Timestamp](#google-protobuf-Timestamp) |  | The latest time at which a process in this process group was observed to exit. |
| first_start_time | [google.protobuf.Timestamp](#google-protobuf-Timestamp) |  | The first time a process in this process group was observed to start. |
| execution_count | [uint64](#uint64) |  | The total number of times processes in this process group have been executed. |
| exit_count | [uint64](#uint64) |  | The total number of times processes in this process group have exited. |
| exec_ids | [string](#string) | repeated | The most recent exec ids seen for this process group. Although the protobuf format allows for any number of exec ids, only a fixed number of exec ids (currently 8) are saved for a given process group in order to cap memory usage in tetragon ebpf maps. Older exec ids are removed to make room for more recent exec ids. For this reason, this is not guaranteed to have the exec id for every process that has executed with the same process name and arguments. |






<a name="application_model-v1alpha-ApplicationSyscalls"></a>

### ApplicationSyscalls



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| syscalls | [Sys](#application_model-v1alpha-Sys) | repeated |  |
| abi | [Abi](#application_model-v1alpha-Abi) |  |  |






<a name="application_model-v1alpha-ApplicationWorkload"></a>

### ApplicationWorkload



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| name | [string](#string) |  |  |
| kind | [common.k8s.type.v1alpha.WorkloadKind](#common-k8s-type-v1alpha-WorkloadKind) |  |  |
| containers | [ApplicationContainer](#application_model-v1alpha-ApplicationContainer) | repeated | A list of containers below the workload. See ApplicationContainer. |
| uid | [string](#string) |  | UID of the Kubernetes workload. |






<a name="application_model-v1alpha-ConnectionStats"></a>

### ConnectionStats



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| tx_bytes | [uint64](#uint64) |  |  |
| rx_bytes | [uint64](#uint64) |  |  |
| tx_drops | [uint64](#uint64) |  | **Deprecated.** Deprecated: use tx_drop_bytes instead. Despite its name, this field holds a count of dropped transmit bytes, not packets. |
| tx_quota | [uint64](#uint64) |  |  |
| tx_quota_usage | [uint64](#uint64) |  |  |
| last_quota_reset | [google.protobuf.Timestamp](#google-protobuf-Timestamp) |  |  |
| next_quota_reset | [google.protobuf.Timestamp](#google-protobuf-Timestamp) |  |  |
| default_drop_bytes | [uint64](#uint64) |  |  |
| default_allow_bytes | [uint64](#uint64) |  |  |
| sessions | [uint64](#uint64) |  | The cumulative number of TCP connections or UDP sessions observed for this connection over its entire lifespan. This value only increases; consumers can compute deltas by subtracting two consecutive values. |
| tx_drop_bytes | [uint64](#uint64) |  | Number of transmit bytes dropped. Replaces the deprecated tx_drops. |
| tx_drop_packets | [uint64](#uint64) |  | Number of transmit packets dropped. |
| default_drop_packets | [uint64](#uint64) |  | Number of packets dropped by the default policy rule. A subset of tx_drop_packets, which also counts drops an explicit deny rule decided. |
| default_allow_packets | [uint64](#uint64) |  | Number of packets allowed by the default policy rule. |
| rx_drop_bytes | [uint64](#uint64) |  | Number of receive bytes dropped. |
| rx_drop_packets | [uint64](#uint64) |  | Number of receive packets dropped. |
| rx_default_drop_bytes | [uint64](#uint64) |  | Number of receive bytes dropped by the default policy rule. A subset of rx_drop_bytes, which also counts drops an explicit deny rule decided. |
| rx_default_drop_packets | [uint64](#uint64) |  | Number of receive packets dropped by the default policy rule. A subset of rx_drop_packets, which also counts drops an explicit deny rule decided. |
| rx_default_allow_bytes | [uint64](#uint64) |  | Number of receive bytes allowed by the default policy rule. |
| rx_default_allow_packets | [uint64](#uint64) |  | Number of receive packets allowed by the default policy rule. |






<a name="application_model-v1alpha-Destination"></a>

### Destination



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| dns | [DestinationDns](#application_model-v1alpha-DestinationDns) |  |  |
| workload | [DestinationWorkload](#application_model-v1alpha-DestinationWorkload) |  |  |
| ip | [DestinationIP](#application_model-v1alpha-DestinationIP) |  |  |
| port | [uint64](#uint64) |  |  |






<a name="application_model-v1alpha-DestinationDns"></a>

### DestinationDns



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| destination_names | [string](#string) | repeated |  |






<a name="application_model-v1alpha-DestinationIP"></a>

### DestinationIP



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| ip | [string](#string) |  |  |






<a name="application_model-v1alpha-DestinationWorkload"></a>

### DestinationWorkload



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| name | [string](#string) |  |  |
| namespace | [string](#string) |  |  |
| kind | [common.k8s.type.v1alpha.WorkloadKind](#common-k8s-type-v1alpha-WorkloadKind) |  |  |
| resource_kind | [common.k8s.type.v1alpha.ResourceKind](#common-k8s-type-v1alpha-ResourceKind) |  |  |
| uid | [string](#string) |  | UID of the Kubernetes resource. |






<a name="application_model-v1alpha-GetModelRequest"></a>

### GetModelRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| namespaces | [string](#string) | repeated | Namespaces to collect model for. |
| host | [bool](#bool) |  | Include model request information for the host |






<a name="application_model-v1alpha-GetModelResponse"></a>

### GetModelResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| model | [ApplicationModelEvent](#application_model-v1alpha-ApplicationModelEvent) |  |  |






<a name="application_model-v1alpha-NetworkConnectTelemetry"></a>

### NetworkConnectTelemetry



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| id | [string](#string) |  | An opaque identifier that is unique to this telemetry event across all the telemetry types. |
| time | [google.protobuf.Timestamp](#google-protobuf-Timestamp) |  | Timestamp at which this telemetry event got transmitted. |
| event_type | [TelemetryType](#application_model-v1alpha-TelemetryType) |  | Telemetry event type. This field is set to `TELEMETRY_TYPE_NETWORK_CONNECT`. |
| cluster_name | [string](#string) |  | Name of the cluster that transmitted this telemetry event. |
| node_name | [string](#string) |  | Name of the node that transmitted this telemetry event. |
| node_labels | [NetworkConnectTelemetry.NodeLabelsEntry](#application_model-v1alpha-NetworkConnectTelemetry-NodeLabelsEntry) | repeated | Labels of the node that transmitted this telemetry event. For nodes that belong to a Kubernetes cluster, this field contains Kubernetes node labels. For cloud provider VMs (e.g. AWS, GCP, Azure) that do not belong to any Kubernetes cluster, this field may contain VM tags / labels. |
| kubernetes_namespace | [string](#string) |  | Kubernetes namespace in which the process that received this policy verdict is running. This field is set if and only if the process belongs to a Kubernetes workload. |
| kubernetes_workload_kind | [common.k8s.type.v1alpha.WorkloadKind](#common-k8s-type-v1alpha-WorkloadKind) |  | Kubernetes workload kind of the process that received this policy verdict. This field is set if and only if the process belongs to a Kubernetes workload. |
| kubernetes_workload_name | [string](#string) |  | Kubernetes workload name of the process that received this policy verdict. This field is set if and only if the process belongs to a Kubernetes workload. |
| process_hash | [string](#string) |  | Hash of the process that received this policy verdict. TODO: Document how the hash is calculated. |
| process_name | [string](#string) |  | Name of the process that received this policy verdict. |
| process_arguments | [string](#string) |  | Arguments of the process that received this policy verdict. |
| destination_name | [string](#string) |  | Destination name of the connection (e.g. &#34;tetragon.io&#34;) that received this network connect policy verdict. |
| destination_type | [DestinationType](#application_model-v1alpha-DestinationType) |  | Destination type of the connection that received this network connect policy verdict. |
| destination_port | [uint32](#uint32) |  | Destination port of the connection that received this network connect policy verdict. |
| destination_kubernetes_namespace | [string](#string) |  | Kubernetes namespace of the destination workload. This field is set if and only if destination_type is `DESTINATION_TYPE_KUBERNETES`. |
| destination_kubernetes_resource_kind | [common.k8s.type.v1alpha.ResourceKind](#common-k8s-type-v1alpha-ResourceKind) |  | Kubernetes resource kind of the process that received the policy verdict. |
| destination_kubernetes_resource_name | [string](#string) |  | Kubernetes workload name of the destination. This field is set if and only if destination_type is `DESTINATION_TYPE_KUBERNETES`. |
| destination_kubernetes_service_kind | [common.k8s.type.v1alpha.ServiceKind](#common-k8s-type-v1alpha-ServiceKind) |  | Kubernetes service kind of the process that received this policy verdict. This field is set if and only if the process resource kind is service. |
| destination_kubernetes_workload_kind | [common.k8s.type.v1alpha.WorkloadKind](#common-k8s-type-v1alpha-WorkloadKind) |  | Kubernetes workload kind of the destination. This field is set if and only if destination_type is `DESTINATION_TYPE_KUBERNETES`. |
| protocol | [common.net.v1alpha.IPProtocol](#common-net-v1alpha-IPProtocol) |  | Network protocol of the connection that received this network connect policy verdict. |
| verdict | [PolicyVerdict](#application_model-v1alpha-PolicyVerdict) |  | Policy verdict. If the connections don&#39;t have corresponding policy rules, this field is set to POLICY_VERDICT_UNSPECIFIED. |
| policy_name | [string](#string) |  | Name of the Tetragon network connect policy that made this verdict. If the connections don&#39;t have corresponding policy rules, this field is not set. |
| rule_name | [string](#string) |  | Name of the Tetragon network connect policy rule that made this verdict. If the connections don&#39;t have corresponding policy rules, this field is not set. If the connections were allowed by the default allow rule, this field is set to &#34;tetragon:default-allow&#34;. If the connections were dropped by the default drop rule, this field is set to &#34;tetragon:default-drop&#34;. |
| tx_bytes | [uint64](#uint64) |  | tx_bytes allowed or dropped. For `POLICY_VERDICT_ALLOW` verdict events, this field specifies the number of transmit bytes from connections allowed by the policy rule. For `POLICY_VERDICT_DROP` verdict events, this field is set to zero. |
| rx_bytes | [uint64](#uint64) |  | The number of receive bytes from connections allowed by the policy rule. This field is not set for `POLICY_VERDICT_DROP` verdict events. |
| sessions | [uint64](#uint64) |  | The number of TCP connections / UDP sessions. For `POLICY_VERDICT_UNSPECIFIED` verdict events, this field specifies the number of TCP connections / UDP sessions created. For `POLICY_VERDICT_ALLOW` verdict events, this field specifies the number of TCP connections / UDP sessions allowed by this policy rule. For `POLICY_VERDICT_DROP` verdict events, this field specifies the number of dropped TCP connections / UDP sessions dropped by this policy rule. |
| application_model_id | [string](#string) |  | The ID of the application model from which this telemetry data got derived. |
| tx_drops | [uint64](#uint64) |  | **Deprecated.** Deprecated: use tx_drop_bytes instead. Despite its name, this field holds a count of dropped transmit bytes, not packets. |
| container | [ApplicationContainer](#application_model-v1alpha-ApplicationContainer) |  | The container in which this connection has an endpoint |
| tx_drop_packets | [uint64](#uint64) |  | The number of transmit packets dropped over the interval since the previous telemetry event. Feeds EdgeTypeNetworkTelemetry.network_transmit_drop_total, and also network_transmit_drop_policy_total when every drop the producer counts here was a policy decision. |
| tx_drop_bytes | [uint64](#uint64) |  | The number of transmit bytes dropped over the interval since the previous telemetry event. Replaces the deprecated tx_drops. |
| default_drop_bytes | [uint64](#uint64) |  | The number of transmit bytes dropped by the default policy rule over the interval since the previous telemetry event. |
| default_allow_bytes | [uint64](#uint64) |  | The number of transmit bytes allowed by the default policy rule over the interval since the previous telemetry event. |
| default_drop_packets | [uint64](#uint64) |  | The number of transmit packets dropped by the default policy rule over the interval since the previous telemetry event. A subset of tx_drop_packets, which also counts drops an explicit deny rule decided. |
| default_allow_packets | [uint64](#uint64) |  | The number of transmit packets allowed by the default policy rule over the interval since the previous telemetry event. |
| rx_drop_bytes | [uint64](#uint64) |  | The number of receive bytes dropped over the interval since the previous telemetry event. |
| rx_drop_packets | [uint64](#uint64) |  | The number of receive packets dropped over the interval since the previous telemetry event. Feeds EdgeTypeNetworkTelemetry.network_receive_drop_total, and also network_receive_drop_policy_total when every drop the producer counts here was a policy decision. |
| rx_default_drop_bytes | [uint64](#uint64) |  | The number of receive bytes dropped by the default policy rule over the interval since the previous telemetry event. |
| rx_default_drop_packets | [uint64](#uint64) |  | The number of receive packets dropped by the default policy rule over the interval since the previous telemetry event. A subset of rx_drop_packets, which also counts drops an explicit deny rule decided. |
| rx_default_allow_bytes | [uint64](#uint64) |  | The number of receive bytes allowed by the default policy rule over the interval since the previous telemetry event. |
| rx_default_allow_packets | [uint64](#uint64) |  | The number of receive packets allowed by the default policy rule over the interval since the previous telemetry event. |
| kubernetes_workload_uid | [string](#string) |  | UID of the Kubernetes workload from which the connection originated. |
| destination_kubernetes_resource_uid | [string](#string) |  | UID of the destination Kubernetes resource. |
| observation_point | [ObservationPoint](#application_model-v1alpha-ObservationPoint) |  | Side of the connection from which the observer saw this network connect policy verdict. |






<a name="application_model-v1alpha-NetworkConnectTelemetry-NodeLabelsEntry"></a>

### NetworkConnectTelemetry.NodeLabelsEntry



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| key | [string](#string) |  |  |
| value | [string](#string) |  |  |






<a name="application_model-v1alpha-NetworkPolicy"></a>

### NetworkPolicy



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| verdict | [PolicyVerdict](#application_model-v1alpha-PolicyVerdict) |  | Policy verdict. If the connections don&#39;t have corresponding policy rules, this field is set to POLICY_VERDICT_UNSPECIFIED. |
| policy_name | [string](#string) |  | Name of the Tetragon network connect policy that made this verdict. If the connections don&#39;t have corresponding policy rules, this field is not set. |
| rule_name | [string](#string) |  | Name of the Tetragon network connect policy rule that made this verdict. If the connections don&#39;t have corresponding policy rules, this field is not set. If the connections were allowed by the default allow rule, this field is set to &#34;tetragon:default-allow&#34;. If the connections were dropped by the default drop rule, this field is set to &#34;tetragon:default-drop&#34;. |






<a name="application_model-v1alpha-ProcessTelemetry"></a>

### ProcessTelemetry



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| cluster_name | [string](#string) |  |  |
| node_name | [string](#string) |  |  |
| event_type | [TelemetryType](#application_model-v1alpha-TelemetryType) |  |  |
| time | [google.protobuf.Timestamp](#google-protobuf-Timestamp) |  |  |
| kubernetes_namespace | [string](#string) |  |  |
| kubernetes_workload_name | [string](#string) |  |  |
| kubernetes_workload_kind | [common.k8s.type.v1alpha.WorkloadKind](#common-k8s-type-v1alpha-WorkloadKind) |  |  |
| process_hash | [string](#string) |  |  |
| process_name | [string](#string) |  |  |
| process_arguments | [string](#string) |  |  |
| execution_count | [uint64](#uint64) |  |  |
| parent_hash | [string](#string) |  |  |
| id | [string](#string) |  | An opaque identifier that is unique to this telemetry data across all the telemetry types. |
| node_labels | [ProcessTelemetry.NodeLabelsEntry](#application_model-v1alpha-ProcessTelemetry-NodeLabelsEntry) | repeated | Labels of the node that transmitted this telemetry event. For nodes that belong to a Kubernetes cluster, this field contains Kubernetes node labels. For cloud provider VMs (e.g. AWS, GCP, Azure) that do not belong to any Kubernetes cluster, this field may contain VM tags / labels. |
| application_model_id | [string](#string) |  | The ID of the application model from which this telemetry data got derived. |
| first_start_time | [google.protobuf.Timestamp](#google-protobuf-Timestamp) |  | The first time the process has been observed to run. |
| latest_start_time | [google.protobuf.Timestamp](#google-protobuf-Timestamp) |  | The most recent time the process has been observed to run. |
| parent_names | [string](#string) | repeated | Names of all processes that have been parents of this name/argument tuple. |
| container | [ApplicationContainer](#application_model-v1alpha-ApplicationContainer) |  | The container in which this process is running |
| exit_count | [uint64](#uint64) |  | The total number of times processes in this process group have exited. |
| kubernetes_workload_uid | [string](#string) |  | UID of the Kubernetes workload in which the process is running. |






<a name="application_model-v1alpha-ProcessTelemetry-NodeLabelsEntry"></a>

### ProcessTelemetry.NodeLabelsEntry



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| key | [string](#string) |  |  |
| value | [string](#string) |  |  |






<a name="application_model-v1alpha-StreamModelFragmentsRequest"></a>

### StreamModelFragmentsRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| namespaces | [string](#string) | repeated | Namespaces to collect model for. |
| host | [bool](#bool) |  | Include model request information for the host |






<a name="application_model-v1alpha-StreamModelFragmentsResponse"></a>

### StreamModelFragmentsResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| model_fragment | [ApplicationModelFragment](#application_model-v1alpha-ApplicationModelFragment) |  |  |






<a name="application_model-v1alpha-StreamModelRequest"></a>

### StreamModelRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| namespaces | [string](#string) | repeated | Namespaces to collect model for. |
| host | [bool](#bool) |  | Include model request information for the host |






<a name="application_model-v1alpha-StreamModelResponse"></a>

### StreamModelResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| model | [ApplicationModelEvent](#application_model-v1alpha-ApplicationModelEvent) |  |  |






<a name="application_model-v1alpha-StreamTelemetryRequest"></a>

### StreamTelemetryRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| namespaces | [string](#string) | repeated | Namespaces to collect model for. |
| host | [bool](#bool) |  | Include model request information for the host |






<a name="application_model-v1alpha-StreamTelemetryResponse"></a>

### StreamTelemetryResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| process | [ProcessTelemetry](#application_model-v1alpha-ProcessTelemetry) |  |  |
| network_connect | [NetworkConnectTelemetry](#application_model-v1alpha-NetworkConnectTelemetry) |  |  |





 


<a name="application_model-v1alpha-DestinationType"></a>

### DestinationType


| Name | Number | Description |
| ---- | ------ | ----------- |
| DESTINATION_TYPE_UNSPECIFIED | 0 |  |
| DESTINATION_TYPE_DNS | 1 |  |
| DESTINATION_TYPE_CIDR | 2 |  |
| DESTINATION_TYPE_KUBERNETES | 3 |  |



<a name="application_model-v1alpha-ObservationPoint"></a>

### ObservationPoint
ObservationPoint identifies, relative to a connection&#39;s direction, the side
from which the observer saw the connection. An ApplicationConnection always
hangs off the observing process&#39;s own process group, so unlike
graph.v1alpha.ObservationPoint this has no intermediate value.

| Name | Number | Description |
| ---- | ------ | ----------- |
| OBSERVATION_POINT_UNSPECIFIED | 0 |  |
| OBSERVATION_POINT_SOURCE | 1 |  |
| OBSERVATION_POINT_DESTINATION | 2 |  |



<a name="application_model-v1alpha-PolicyVerdict"></a>

### PolicyVerdict


| Name | Number | Description |
| ---- | ------ | ----------- |
| POLICY_VERDICT_UNSPECIFIED | 0 |  |
| POLICY_VERDICT_ALLOW | 1 |  |
| POLICY_VERDICT_DROP | 2 |  |



<a name="application_model-v1alpha-TelemetryType"></a>

### TelemetryType


| Name | Number | Description |
| ---- | ------ | ----------- |
| TELEMETRY_TYPE_UNSPECIFIED | 0 |  |
| TELEMETRY_TYPE_PROCESS | 1 |  |
| TELEMETRY_TYPE_NETWORK_CONNECT | 2 |  |


 

 


<a name="application_model-v1alpha-ApplicationModelService"></a>

### ApplicationModelService


| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| GetModel | [GetModelRequest](#application_model-v1alpha-GetModelRequest) | [GetModelResponse](#application_model-v1alpha-GetModelResponse) |  |
| StreamModel | [StreamModelRequest](#application_model-v1alpha-StreamModelRequest) | [StreamModelResponse](#application_model-v1alpha-StreamModelResponse) stream | This returns the same information as GetModel, but split into smaller partial messages. Each partial message will contain a sub-tree from the root, but only for a selected application host, namespace, and/or workload. The client should combine the partial messages, merging as needed, to obtain the entire Application Model. |
| StreamModelFragments | [StreamModelFragmentsRequest](#application_model-v1alpha-StreamModelFragmentsRequest) | [StreamModelFragmentsResponse](#application_model-v1alpha-StreamModelFragmentsResponse) stream | This will replace StreamModel once the corresponding hubble-fgs PR is merged. |
| StreamTelemetry | [StreamTelemetryRequest](#application_model-v1alpha-StreamTelemetryRequest) | [StreamTelemetryResponse](#application_model-v1alpha-StreamTelemetryResponse) stream |  |

 



## Scalar Value Types

| .proto Type | Notes | C++ | Java | Python | Go | C# | PHP | Ruby |
| ----------- | ----- | --- | ---- | ------ | -- | -- | --- | ---- |
| <a name="double" /> double |  | double | double | float | float64 | double | float | Float |
| <a name="float" /> float |  | float | float | float | float32 | float | float | Float |
| <a name="int32" /> int32 | Uses variable-length encoding. Inefficient for encoding negative numbers – if your field is likely to have negative values, use sint32 instead. | int32 | int | int | int32 | int | integer | Bignum or Fixnum (as required) |
| <a name="int64" /> int64 | Uses variable-length encoding. Inefficient for encoding negative numbers – if your field is likely to have negative values, use sint64 instead. | int64 | long | int/long | int64 | long | integer/string | Bignum |
| <a name="uint32" /> uint32 | Uses variable-length encoding. | uint32 | int | int/long | uint32 | uint | integer | Bignum or Fixnum (as required) |
| <a name="uint64" /> uint64 | Uses variable-length encoding. | uint64 | long | int/long | uint64 | ulong | integer/string | Bignum or Fixnum (as required) |
| <a name="sint32" /> sint32 | Uses variable-length encoding. Signed int value. These more efficiently encode negative numbers than regular int32s. | int32 | int | int | int32 | int | integer | Bignum or Fixnum (as required) |
| <a name="sint64" /> sint64 | Uses variable-length encoding. Signed int value. These more efficiently encode negative numbers than regular int64s. | int64 | long | int/long | int64 | long | integer/string | Bignum |
| <a name="fixed32" /> fixed32 | Always four bytes. More efficient than uint32 if values are often greater than 2^28. | uint32 | int | int | uint32 | uint | integer | Bignum or Fixnum (as required) |
| <a name="fixed64" /> fixed64 | Always eight bytes. More efficient than uint64 if values are often greater than 2^56. | uint64 | long | int/long | uint64 | ulong | integer/string | Bignum |
| <a name="sfixed32" /> sfixed32 | Always four bytes. | int32 | int | int | int32 | int | integer | Bignum or Fixnum (as required) |
| <a name="sfixed64" /> sfixed64 | Always eight bytes. | int64 | long | int/long | int64 | long | integer/string | Bignum |
| <a name="bool" /> bool |  | bool | boolean | boolean | bool | bool | boolean | TrueClass/FalseClass |
| <a name="string" /> string | A string must always contain UTF-8 encoded or 7-bit ASCII text. | string | String | str/unicode | string | string | string | String (UTF-8) |
| <a name="bytes" /> bytes | May contain any arbitrary sequence of bytes. | string | ByteString | str | []byte | ByteString | string | String (ASCII-8BIT) |

