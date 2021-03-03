
/**
 * Process filters
 * see generic_process_filter below
 */

#define FIND_PIDSET(value)  {				\
	if (!filter)					\
		return 0;				\
	if (filter->key.pid == value ||			\
	    filter->pkey.pid == value) {		\
			pidset_found = true;		\
			goto accept;			\
	}						\
	filter = map_lookup_event(filter->pkey.pid);	\
}

#define FIND_PIDSET10(VAL) {	\
	FIND_PIDSET(VAL)	\
	FIND_PIDSET(VAL)	\
	FIND_PIDSET(VAL)	\
	FIND_PIDSET(VAL)	\
	FIND_PIDSET(VAL)	\
	FIND_PIDSET(VAL)	\
	FIND_PIDSET(VAL)	\
	FIND_PIDSET(VAL)	\
	FIND_PIDSET(VAL)	\
}

#define FILTER_PIDSET(VAL) {	\
	FIND_PIDSET10(VAL)	\
}

#define FIND_NSPIDSET(value)  {				\
	if (!filter)					\
		return 0;				\
	if (filter->nspid == value) {			\
		nspidset_found = true;			\
		goto nspid_accept;			\
	}						\
	filter = map_lookup_event(filter->pkey.pid);	\
}

#define FIND_NSPIDSET10(VAL) {	\
	FIND_NSPIDSET(VAL)	\
	FIND_NSPIDSET(VAL)	\
	FIND_NSPIDSET(VAL)	\
	FIND_NSPIDSET(VAL)	\
	FIND_NSPIDSET(VAL)	\
	FIND_NSPIDSET(VAL)	\
	FIND_NSPIDSET(VAL)	\
	FIND_NSPIDSET(VAL)	\
	FIND_NSPIDSET(VAL)	\
}

#define FILTER_NSPIDSET(VAL) {	\
	FIND_NSPIDSET10(VAL)	\
}

static inline __attribute__((always_inline))
bool filter_pidset(int pid, struct execve_map_value *enter)
{
	struct execve_map_value *filter = enter;
	bool pidset_found = false;

	FIND_PIDSET10(pid);
accept:
	return pidset_found;
}

static inline __attribute__((always_inline))
bool filter_nspidset(int nspid, struct execve_map_value *enter)
{
	struct execve_map_value *filter = enter;
	bool nspidset_found = false;

	FIND_NSPIDSET10(nspid);
nspid_accept:
	return nspidset_found;
}

static inline __attribute__((always_inline))
bool filter_pidsets(struct execve_map_value *enter)
{
	enum generic_func_args_enum fgs_args;

	int pidset_filter_value = bpf_core_enum_value(fgs_args, pidset_value);
	int notpidset_filter_value = bpf_core_enum_value(fgs_args, notpidset_value);
	int nspidset_filter_value = bpf_core_enum_value(fgs_args, nspidset_value);
	int notnspidset_filter_value = bpf_core_enum_value(fgs_args, notnspidset_value);

	if (pidset_filter_value) {
		bool found = filter_pidset(pidset_filter_value, enter);

		if (!found)
			return 0;
	}

	if (notpidset_filter_value) {
		bool found = filter_pidset(notpidset_filter_value, enter);

		if (found)
			return 0;
	}

	if (nspidset_filter_value) {
		bool found = filter_nspidset(nspidset_filter_value, enter);

		if (!found)
			return 0;
	}

	if (notnspidset_filter_value) {
		bool found = filter_nspidset(notnspidset_filter_value, enter);

		if (found)
			return 0;
	}

	return true;
}

// generic_process_filter return value
enum  {
	PFILTER_PASSED = 0,          // filter check passed
	PFILTER_FAILED = -1,         // filter check failed
	PFILTER_CURR_NOT_FOUND = -2, // event_find_curr() failed
};

// generic_process_filter performs filtering based on pid/nspid
//
// if filter check was successful, it will return PFILTER_PASSED and properly
// set the values of:
//    current->pid
//    current->ktime
// for the memory located at index 0 of @msg_heap assuming the value follows the
// msg_generic_hdr structure.
static inline  __attribute__((always_inline))
int generic_process_filter(struct msg_execve_key *current)
{
	struct execve_map_value *enter;
	bool walker = 0;
	__u32 ppid;

	enter = event_find_curr(&ppid, 0, &walker);
	if (enter) {
		enum generic_func_args_enum fgs_args;

		int nspid_filter_ty = bpf_core_enum_value(fgs_args, nspid_type);
		int nspid_filter_value = bpf_core_enum_value(fgs_args, nspid_value);
		int pid_filter_ty = bpf_core_enum_value(fgs_args, pid_type);
		int pid_filter_value = bpf_core_enum_value(fgs_args, pid_value);
		bool accept_pid;

		if (nspid_filter_ty == op_filter_lt) {
			if (enter->nspid < nspid_filter_value)
				return PFILTER_FAILED;
		} else if (nspid_filter_ty == op_filter_gt) {
			if (enter->nspid > nspid_filter_value)
				return PFILTER_FAILED;
		} else if (nspid_filter_ty == op_filter_eq) {
			if (enter->nspid == nspid_filter_value)
				return PFILTER_FAILED;
		}

		if (pid_filter_ty == op_filter_lt) {
			if (enter->key.pid < pid_filter_value)
				return PFILTER_FAILED;
		} else if (pid_filter_ty == op_filter_gt) {
			if (enter->key.pid > pid_filter_value)
				return PFILTER_FAILED;
		} else if (pid_filter_ty == op_filter_eq) {
			if (enter->key.pid == pid_filter_value)
				return PFILTER_FAILED;
		}

		accept_pid = filter_pidsets(enter);
		if (!accept_pid)
			return PFILTER_FAILED;

		current->pid = enter->key.pid;
		current->ktime = enter->key.ktime;
		return PFILTER_PASSED;
	}

	return PFILTER_CURR_NOT_FOUND;
}
