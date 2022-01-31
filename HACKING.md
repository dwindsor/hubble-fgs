# Hacking FGS

Various topics for hacking FGS.

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



