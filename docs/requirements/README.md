# Requirements

## Linux Kernel

### Version

Minimum required kernel version is 4.19.


### Config Options

Control Groups:
```
    CONFIG_CGROUPS=y        Control Group support
    CONFIG_MEMCG=y          Memory Control group
    CONFIG_BLK_CGROUP=y     Generic block IO controller
    CONFIG_CGROUP_SCHED=y
    CONFIG_CGROUP_PIDS=y    Process Control group
    CONFIG_CGROUP_FREEZER=y Freeze and unfreeze tasks controller
    CONFIG_CPUSETS=y        Manage CPUSETs
    CONFIG_PROC_PID_CPUSET=y
    CONFIG_CGROUP_DEVICE=Y  Devices Control group
    CONFIG_CGROUP_CPUACCT=y CPU accouting controller
    CONFIG_CGROUP_PERF=y
    CONFIG_CGROUP_BPF=y     Attach eBPF programs to a cgroup

    CGROUP_FAVOR_DYNMODS=y  (optional)  >= 6.0
        Reduces the latencies of dynamic cgroup modifications at the
        cost of making hot path operations such as forks and exits
        more expensive.
        Platforms with frequent cgroup migrations could enable this
        option as a potential alleviation for pod and containers
        association issues.
```

## Control Groups Usage

FGS uses Cgroups to keep track of processes and containers. By default, it supports both Cgroup v1 and v2 interfaces. For more details on Cgroup internals please see [References](#references).

In general, we recommend our users switch to Cgroup version 2 by default as most of the new kernel features are Cgroupv2 compatible only.

- For Kubernetes deployments, please read the [Kubernetes cgroups architecture document](https://kubernetes.io/docs/concepts/architecture/cgroups/).


If you are unable to run Cgroupv2, Cgroupv1 is also supported assuming:

1. Your kernel supports all required Cgroup configs. Please see [Kernel Config options](#config-options) and ensure that relevant Cgroup config options are enabled.

2. Your Kubernetes and container runtime properly set the following Cgroup controllers: `cpuset`, `memory`, and `pids`. This is often the case by default.


### Control Groups detection

During startup, FGS will transparently check the current Cgroup configuration, choose and adapt to the best options. FGS will log relevant Cgroup discovery information for debugging. Please see the subsections below for log output examples under various Cgroup configurations.

#### K8s deployment under Cgroupv1

logs:
```
time="2022-11-24T14:43:33Z" level=info msg="Cgroup mode detection succeeded" cgroup.fs=/sys/fs/cgroup cgroup.mode="Legacy mode (Cgroupv1)"

time="2022-11-24T14:43:33Z" level=info msg="Supported cgroup controller 'memory' is active on the system" cgroup.controller.hierarchyID=12 cgroup.controller.index=4 cgroup.controller.name=memory cgroup.fs=/sys/fs/cgroup

time="2022-11-24T14:43:33Z" level=info msg="Supported cgroup controller 'pids' is active on the system" cgroup.controller.hierarchyID=6 cgroup.controller.index=11 cgroup.controller.name=pids cgroup.fs=/sys/fs/cgroup

time="2022-11-24T14:43:33Z" level=info msg="Supported cgroup controller 'cpuset' is active on the system" cgroup.controller.hierarchyID=13 cgroup.controller.index=0 cgroup.controller.name=cpuset cgroup.fs=/sys/fs/cgroup

time="2022-11-24T14:43:33Z" level=info msg="Cgroupv1 controller 'memory' will be used" cgroup.controller.hierarchyID=12 cgroup.controller.index=4 cgroup.controller.name=memory cgroup.fs=/sys/fs/cgroup

time="2022-11-24T14:43:33Z" level=info msg="Cgroupv1 hierarchy validated successfully" cgroup.fs=/sys/fs/cgroup cgroup.path=/sys/fs/cgroup/memory

time="2022-11-24T14:43:33Z" level=info msg="Deployment mode detection succeeded" cgroup.fs=/sys/fs/cgroup deployment.mode=Kubernetes

time="2022-11-24T14:43:33Z" level=info msg="Updated FGSConf map successfully" NSPID=1 cgroup.controller.hierarchyID=12 cgroup.controller.index=4 cgroup.controller.name=memory cgroup.fs.magic=Cgroupv1 confmap-update=tg_conf_map deployment.mode=Kubernetes log.level=info

time="2022-11-24T14:43:33Z" level=info msg="Listening for events..."
```

#### K8s deployment under Cgroupv2

logs:
```
time="2022-11-24T14:34:12Z" level=info msg="Cgroup mode detection succeeded" cgroup.fs=/sys/fs/cgroup cgroup.mode="Unified mode (Cgroupv2)"

time="2022-11-24T14:34:12Z" level=info msg="Supported cgroup controller 'memory' is active on the system" cgroup.controller.hierarchyID=0 cgroup.controller.index=4 cgroup.controller.name=memory cgroup.fs=/sys/fs/cgroup

time="2022-11-24T14:34:12Z" level=info msg="Supported cgroup controller 'pids' is active on the system" cgroup.controller.hierarchyID=0 cgroup.controller.index=11 cgroup.controller.name=pids cgroup.fs=/sys/fs/cgroup

time="2022-11-24T14:34:12Z" level=info msg="Supported cgroup controller 'cpuset' is active on the system" cgroup.controller.hierarchyID=0 cgroup.controller.index=0 cgroup.controller.name=cpuset cgroup.fs=/sys/fs/cgroup

time="2022-11-24T14:34:12Z" level=info msg="Cgroupv2 supported controllers detected successfully" cgroup.controllers="[cpuset cpu io memory hugetlb pids rdma misc]" cgroup.fs=/sys/fs/cgroup

time="2022-11-24T14:34:12Z" level=info msg="Cgroupv2 controller 'memory' will be used as a fallback for the default hierarchy" cgroup.controller.hierarchyID=0 
cgroup.controller.index=4 cgroup.controller.name=memory cgroup.fs=/sys/fs/cgroup

time="2022-11-24T14:34:12Z" level=info msg="Cgroupv2 hierarchy validated successfully" cgroup.fs=/sys/fs/cgroup cgroup.path=/sys/fs/cgroup/init.scope

time="2022-11-24T14:34:12Z" level=info msg="Deployment mode detection succeeded" cgroup.fs=/sys/fs/cgroup deployment.mode=Kubernetes

time="2022-11-24T14:34:12Z" level=info msg="Updated FGSConf map successfully" NSPID=1 cgroup.controller.hierarchyID=0 cgroup.controller.index=4 cgroup.controller.name=memory cgroup.fs.magic=Cgroupv2 confmap-update=tg_conf_map deployment.mode=Kubernetes log.level=info

time="2022-11-24T14:34:12Z" level=info msg="Listening for events..."

```

#### K8s deployment under Cgroup Hybrid mode

Hybrid mode is a systemd mode that combines Cgroupv1 and Cgroupv2. For more details, please check [systemd Cgroup delegation](https://github.com/systemd/systemd/blob/main/docs/CGROUP_DELEGATION.md)

logs:
```
time="2022-11-24T15:13:54+01:00" level=info msg="Cgroup mode detection succeeded" cgroup.fs=/sys/fs/cgroup cgroup.mode="Hybrid mode (Cgroupv1 and Cgroupv2)"

time="2022-11-24T15:13:54+01:00" level=info msg="Supported cgroup controller 'memory' is active on the system" cgroup.controller.hierarchyID=12 cgroup.controller.index=4 cgroup.controller.name=memory cgroup.fs=/sys/fs/cgroup

time="2022-11-24T15:13:54+01:00" level=info msg="Supported cgroup controller 'pids' is active on the system" cgroup.controller.hierarchyID=6 cgroup.controller.index=11 cgroup.controller.name=pids cgroup.fs=/sys/fs/cgroup

time="2022-11-24T15:13:54+01:00" level=info msg="Supported cgroup controller 'cpuset' is active on the system" cgroup.controller.hierarchyID=13 cgroup.controller.index=0 cgroup.controller.name=cpuset cgroup.fs=/sys/fs/cgroup

time="2022-11-24T15:13:54+01:00" level=info msg="Cgroupv1 controller 'memory' will be used" cgroup.controller.hierarchyID=12 cgroup.controller.index=4 cgroup.controller.name=memory cgroup.fs=/sys/fs/cgroup
```

Note: If detection of the current Cgroup configuration fails, a warning will be printed. Under these circumstances, process association with Kubernetes pods and containers will be limited.


## References

- [Cgroup v2](https://www.kernel.org/doc/Documentation/cgroup-v2.txt)

- [Unified Cgroup Hierarchy](https://docs.kernel.org/admin-guide/cgroup-v2.html).

- [CGROUP_DELEGATION](https://github.com/systemd/systemd/blob/main/docs/CGROUP_DELEGATION.md)

- [Cgroup v1](https://www.kernel.org/doc/Documentation/cgroup-v1/cgroups.txt)

