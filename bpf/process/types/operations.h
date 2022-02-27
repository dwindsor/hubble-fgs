#ifndef __OPERATIONS_H__
#define __OPERATIONS_H__

enum {
	op_filter_none = 0,
	op_filter_gt   = 1,
	op_filter_lt   = 2,
	op_filter_eq   = 3,
	op_filter_neq  = 4,
	// pid and namespace ops
	op_filter_in = 5,
	op_filter_notin = 6,
	// string ops
	op_filter_str_contains = 7,
	op_filter_str_prefix   = 8,
	op_filter_str_postfix  = 9,
};

enum {
	ns_uts = 0,
	ns_ipc = 1,
	ns_mnt = 2,
	ns_pid = 3,
	ns_pid_for_children = 4,
	ns_net = 5,
	ns_time = 6,
	ns_time_for_children = 7,
	ns_cgroup = 8,
	ns_user = 9,
};

#endif // __OPERATIONS_H__
