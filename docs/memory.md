# Measure memory consumption of Tetragon

## Examples

One example of measurements could be https://github.com/isovalent/hubble-fgs/issues/4592#issuecomment-2245837126.
Here are some extracts from it.

| Version | Memory (bytes) | BPF maps pie |
|--------|--------|--------|
| **before**: master (commit 2640daebd8d1640505b309caacbc98f5f3e42771) with default ruleset | `133,681,152` | <img width="945" alt="image" src="https://github.com/user-attachments/assets/c9ff5714-a1d9-40b0-9889-1a2d0d81249b"> |
| **after**: master (commit a6445580d61cd8279e3d85be93ab293dce6448ed with fixes synched) with base sensor | `117,899,264`  | <img width="904" alt="image" src="https://github.com/user-attachments/assets/dbc86d7a-d996-44c4-891e-e1d14e2f09af"> |

| Version | Memory (bytes) | BPF maps pie |
|--------|--------|--------|
| **before**: v1.13 (commit c19ae546bfa9853c390e440ed874121d457f5f73) with default ruleset | `1,622,212,608` | <img width="896" alt="image" src="https://github.com/user-attachments/assets/88bd8a1d-968c-40b4-a1f8-1bc52cb22b0e"> |
| **after**: v1.13 (commit 4468c3b9463cc4ffe7acf38312f2344ad4ae0917) with default ruleset | `295,157,760`  | <img width="887" alt="image" src="https://github.com/user-attachments/assets/e7cbb293-6c6f-4df7-98fe-3205bed3374f"> |

## Methodology

A good way to estimate the memory usage is to use the cgroup v2 memory
accounting (it accounts for BPF maps consumption, while v1 does not[^1]).

Let the Go garbage collector cool down a bit after startup so that you get an
approximation of the real working set memory and not the memory used for
startup. For tetragon, I usually wait a couple minutes, usually you see the
memory go down a little bit around 2min30s.

You can use [`cmemstat`](https://github.com/mtardy/cmemstat), an utility I made
to do exactly that, like this:
```bash
cmemstat sudo ./tetragon --bpf-lib bpf/objs --tracing-policy-dir $(pwd)/install/kubernetes/tetragon/default-policies/
```

A typical output might look like this:
```shell-session
$ cmemstat sleep 2
     uptime         anon         file       kernel        usage   workingset
        1ms         8192            0        20480       262144       262144
      502ms        86016            0        57344       143360       143360
     1.004s        86016            0        57344       143360       143360
     1.506s        86016            0        57344       143360       143360
```

You can see the breakdown between userland memory (2nd column) and kernel
memory (4th column), or just read the total on usage or workinset (5th and 6th
column), most of the time the working set will be equal to the usage[^1]. 

[^1]: See [more details on memory use in the context of Kubernetes, Golang and
    eBPF](https://mtardy.com/posts/memory-kubernetes-golang-ebpf).

To plot a pie chart from the BPF maps `total_bytes_memlock` you can use
[`bpfmemapie`](https://github.com/mtardy/bpfmemapie), or if you just need the
data, more simply.

```shell
sudo bpftool map -j | jq ' group_by(.name) | map({name: .[0].name, total_bytes_memlock: map(.bytes_memlock | tonumber) | add, maps: length}) | sort_by(.total_bytes_memlock)'
```

