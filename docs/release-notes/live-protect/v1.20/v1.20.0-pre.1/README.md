# v1.20.0-pre.1

Features:

* [uprobes: function override](#uprobes-function-override)

## uprobes: function override

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
