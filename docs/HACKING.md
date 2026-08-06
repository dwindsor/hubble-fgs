# Hacking FGS

Various topics for hacking FGS.


## Debugging Tetragon EE

### Enable debug log level

When debugging, it might be useful to change the log level. The default log level is controlled by the log-level option:

* Enable debug level with `--log-level=debug`

* Enable trace level with `--log-level=trace`

### Change log level dynamically

It is possible to change the log level dynamically by sending the corresponding signal to tetragon process.

* Change log level to debug level by sending the `SIGRTMIN+20` signal to tetragon pid:

  ```shell
  sudo kill -s SIGRTMIN+20 $(pidof hubble-fgs)
  ```

* Change log level to trace level by sending the `SIGRTMIN+21` signal to tetragon pid:

  ```shell
  sudo kill -s SIGRTMIN+21 $(pidof hubble-fgs)
  ```

* To Restore the original log level send the `SIGRTMIN+22` signal to tetragon pid:

  ```shell
  sudo kill -s SIGRTMIN+22 $(pidof hubble-fgs)
  ```


## Passing BTF values from the agent to kernel-side

FGS loads the BTF file, and, for BPF programs such as the ones used in generic
kprobes, modifies it to pass information that is specific to the instance that is
being loaded.  This allows to pass values that from a verifiers' perspective are
constants, and can be used to remove/disable bpf code based on their values.

Example: `is_syscall` which is a boolean flag on whether the kprobe we want to
insert monitors a system call or not.


The various flags for generic calls are defined in [vmlinux.h](bpf/include/vmlinux.h):

```
/* User configurable BTF */
enum generic_func_args_enum {
	func_id = 0x1,
	/* arg{0..4}: types of arguments */
	arg0    = 0x2,
	arg1    = 0x3,
	arg2    = 0x4,
	arg3    = 0x5,
	arg4    = 0x6,
	syscall = 0x7,
	/* arg{0..4}m: metadata of arguments */
	arg0m   = 0x8,
	arg1m   = 0x9,
	arg2m   = 0x10,
	arg3m   = 0x11,
	arg4m   = 0x12,
	/* return arguments */
	argreturn = 0x31,
	/* actions enabled */
	sigkill = 0x40,
	/* tcp sock stat sample info */
	send_check_pkt_sample = 0x50,
	/*
	 * Tracepoints are using the same enum as kprobes
	 */
	/* offset of argument fields from ctx pointer */
	t_arg0_ctx_off = 0x100,
	t_arg1_ctx_off = 0x101,
	t_arg2_ctx_off = 0x102,
	t_arg3_ctx_off = 0x103,
	t_arg4_ctx_off = 0x104,
};
```
(NB: we should probably move them elsewhere)

The various flags in agent side:
https://github.com/isovalent/hubble-fgs/blob/04173c81ba672af7c62d042ef710e2613d44b0fc/pkg/observer/generickprobe.go#L58-L71


Setting value from agent (go) side:
https://github.com/isovalent/hubble-fgs/blob/04173c81ba672af7c62d042ef710e2613d44b0fc/pkg/observer/generickprobe.go#L373-L384

Accessing value from bpf side:
https://github.com/isovalent/hubble-fgs/blob/04173c81ba672af7c62d042ef710e2613d44b0fc/bpf/process/generic_calls.h#L99



## What should I do if I see a checker failure?

The tests using checker work by creating an expected pattern executing a series
of steps and then match the resulting logs with the expected pattern. In case of
a failure, you will something like:

```
observer_test_json.go:152: test failed: json file copied to /tmp/hubble-fgs.gotest.TestListenAcceptClose.179286710.json
	Error Trace:	observer_test.go:447
	Error:      	Received unexpected error:
	            	JsonTestCheck failed after 10 retries: jsonTestCheck: failed to match after 230 events: OrderedMultiResponseChecker: only 4/5 matched
	Test:       	TestListenAcceptClose
```

You can then have a look at the expected patterns in the test, and determine
what went wrong.

In this case, the pattern was:
https://github.com/isovalent/hubble-fgs/blob/cc63b8dd490764f5bee6e7c7060c3a6bafa2b968/pkg/observer/observer_test.go#L388-L418

And the issue was that we used an ordered event checker, but the events were out
of order: https://github.com/isovalent/hubble-fgs/pull/1036.

If you can find fix the issue, great! Otherwise, please create an issue that
includes the JSON file and any analysis you performed.

## Automated Code Generation

For lots of reasons, we generate code and other files from templates and
inputs. The GitHub workflows will fail if code should have been generated.

To get a list of useful functions, use:
```
make help
```

### CLI Switches

After modifying the CLI switches in `pkg/option`, run:

```
make generate-flags
```
to generate the documentation.

### Helm Chart Values

After modifying the helm chart values and rules in
`install/kubernetes/enterprise`, run:

```
make -C install/kubernetes
```

### Tracing Policies

After modifying the CRDs in `pkg/k8s/apis/cilium.io/v1alpha1`, run:

```
make crds
```

## Accessing Metrics

Tetragon metrics can be enabled when starting Tetragon by setting the
`--metrics-server=:2112` CLI switch. The metrics can then be obtained by
running:

```
curl localhost:2112/metrics 2>/dev/null
```
or
```
wget -O- localhost:2112/metrics 2>/dev/null
```

The output will be long so `grep` will be helpful.

## Events Output

Tetragon events can be dumped to a rotating file in JSON by specifying the
`--export-filename <file>` CLI switch. The size of the files and the maximum
number to rotate can be specified with
`--export-file-max-size-mb <size in MB>` and
`export-file-max-backups <number of backups>`.

The events can also be captured as they are produced by using the `tetra`
tool:

```
tetra getevents
```

The tetra tool also offers a compact mode that can be useful in some
situations:

```
tetra getevents -o compact
```

### Example of Compact Events

```
🚀 process e338dac4c545 /usr/bin/socat "- UDP4-RECVFROM:7777,ip-add-membership=239.1.1.1:10.0.2.15,fork" 
🚀 process e338dac4c545 /sbin/modprobe "-q -- netdev-10.0.2.15"           
💥 exit    e338dac4c545 /sbin/modprobe "-q -- netdev-10.0.2.15" 1 
🚀 process e338dac4c545 /sbin/modprobe "-q -- 10.0.2.15"                  
💥 exit    e338dac4c545 /sbin/modprobe "-q -- 10.0.2.15" 1       
🤝 igmp-join e338dac4c545 /usr/bin/socat enp0s2 10.0.2.15=>239.1.1.1    
💥 exit    e338dac4c545 /usr/bin/socat "- UDP4-RECVFROM:7777,ip-add-membership=239.1.1.1:10.0.2.15,fork" 130 
📝 igmp-membership-report enp0s2 10.0.2.15=>239.1.1.1
```

