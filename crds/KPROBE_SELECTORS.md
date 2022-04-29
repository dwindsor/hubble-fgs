# Kprobe selectors: syntax and examples

Each kprobe definition has an optional part of selectors. This document describes their syntax and some limitations of the namespace and capability selectors. 

## ```matchNamespaces```

An example syntax is:
```yaml
    - matchNamespaces:
      - namespace: Pid
        operator: In
        values:
        - "4026531836"
        - "4026531835"
```
This will match if: [```Pid``` namespace is ```4026531836```] ```OR``` [```Pid``` namespace is ```4026531835```]

1. ```namespace``` can be: ```Uts```, ```Ipc```, ```Mnt```, ```Pid```, ```PidForChildren```, ```Net```, ```Cgroup```, or ```User```. ```Time``` and ```TimeForChildren``` are also available in Linux >= 5.6.
2. ```operator``` can be ```In``` or ```NotIn```
3. ```values``` can be raw numeric values (i.e. obtained from ```lsns```) or ```"host_ns"``` which will automatically translated to the appropriate value.  

We can have multiple namespace filters. An example is:
```yaml
    selectors:
    - matchNamespaces:
      - namespace: Pid
        operator: In
        values:
        - "4026531836"
        - "4026531835"
      - namespace: Mnt
        operator: In
        values:
        - "4026531833"
        - "4026531834"
```
This will match if: ([```Pid``` namespace is ```4026531836```] ```OR``` [```Pid``` namespace is ```4026531835```]) ```AND``` ([```Mnt``` namespace is ```4026531833```] ```OR``` [```Mnt``` namespace is ```4026531834```])

### Limitations

1. We can have up to 4 ```values```. These can be both numeric and ```host_ns``` inside a single ```namespace```.
2. We can have up to 4 ```namespace``` values under ```matchNamespaces``` in Linux kernel < 5.3. In Linux >= 5.3 we can have up to 10 values (i.e. the maximum number of namespaces that modern kernels provide).

### Examples

“Generate a kprobe event if ```/etc/shadow``` was opened by ```/bin/cat``` which either had host ```Net``` or ```Mnt``` namespace access”

```yaml
apiVersion: isovalent.com/v1alpha1
kind: TracingPolicy
metadata:
  name: "example1"
spec:
  kprobes:
    - call: "fd_install"
      syscall: false
      args:
        - index: 0
          type: int
        - index: 1
          type: "file"
      selectors:
        - matchBinaries:
          - operator: "In"
            values:
            - "/bin/cat"
          matchArgs:
          - index: 1
            operator: "Equal"
            values:
            - "/etc/shadow"
          matchNamespaces:
          - namespace: Mnt
            operator: In
            values:
            - "host_ns"
        - matchBinaries:
          - operator: "In"
            values:
            - "/bin/cat"
          matchArgs:
          - index: 1
            operator: "Equal"
            values:
            - "/etc/shadow"
          matchNamespaces:
          - namespace: Net
            operator: In
            values:
            - "host_ns"
```

This example has 2 ```selectors```. Note that each selector starts with ```"-"```.

Selector 1:
```yaml
        - matchBinaries:
          - operator: "In"
            values:
            - "/bin/cat"
          matchArgs:
          - index: 1
            operator: "Equal"
            values:
            - "/etc/shadow"
          matchNamespaces:
          - namespace: Mnt
            operator: In
            values:
            - "host_ns"
```
Selector 2:
```yaml
        - matchBinaries:
          - operator: "In"
            values:
            - "/bin/cat"
          matchArgs:
          - index: 1
            operator: "Equal"
            values:
            - "/etc/shadow"
          matchNamespaces:
          - namespace: Net
            operator: In
            values:
            - "host_ns"
```

We have ```[```Selector1 ```OR``` Selector2```]```. Inside each selector we have ```filters```. Both selectors have have 3 filters (i.e. ```matchBinaries```, ```matchArgs```, and ```matchNamespaces```) with different arguments. Adding a ```"-"``` in the beginning of a filter will result in a new selector. 

So the previous CRD will match if:

```[```binary == /bin/cat ```AND``` arg1 == /etc/shadow ```AND``` MntNs == host```]``` ```OR``` ```[```binary == /bin/cat ```AND``` arg1 == /etc/shadow ```AND``` NetNs is host```]```

We can modify the previous example as follows:

“Generate a kprobe event if ```/etc/shadow``` was opened by ```/bin/cat``` which has host ```Net``` and ```Mnt``` namespace access”

```yaml
apiVersion: isovalent.com/v1alpha1
kind: TracingPolicy
metadata:
  name: "example1"
spec:
  kprobes:
    - call: "fd_install"
      syscall: false
      args:
        - index: 0
          type: int
        - index: 1
          type: "file"
      selectors:
        - matchBinaries:
          - operator: "In"
            values:
            - "/bin/cat"
          matchArgs:
          - index: 1
            operator: "Equal"
            values:
            - "/etc/shadow"
          matchNamespaces:
          - namespace: Mnt
            operator: In
            values:
            - "host_ns"
          - namespace: Net
            operator: In
            values:
            - "host_ns"
```

Here we have a single selector. This CRD will match if:

```[```binary == /bin/cat ```AND``` arg1 == /etc/shadow ```AND``` ```(```MntNs == host ```AND``` NetNs == host```)``` ```]``` 

## ```matchCapabilities```

An example syntax is:
```yaml
    - matchCapabilities:
      - type: Effective
        operator: In
        values:
        - "CAP_CHOWN"
        - "CAP_NET_RAW"
```

This will match if: [```Effective``` capabilities contain ```CAP_CHOWN```] OR [```Effective``` capabilities contain ```CAP_NET_RAW```]

1. ```type``` can be: ```Effective```, ```Inheritable```, or ```Permitted```.
2. ```operator``` can be ```In``` or ```NotIn```
3. ```values``` can be any supported capability. A list of all supported capabilities can be found in ```/usr/include/linux/capability.h```.

### Limitations

1. There is no limit in the number of capabilities listed under ```values```.
2. Only one ```type``` field can be specified under ```matchCapabilities```.
