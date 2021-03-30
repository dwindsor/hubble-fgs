#ifndef __OPERATIONS_H__
#define __OPERATIONS_H__

enum {
	op_filter_none = 0,
	op_filter_gt   = 1,
	op_filter_lt   = 2,
	op_filter_eq   = 3,
	op_filter_neq  = 4,
	// string ops
	op_filter_str_contains = 5,
	op_filter_str_prefix   = 6,
	op_filter_str_postfix  = 7,
};

#endif // __OPERATIONS_H__
