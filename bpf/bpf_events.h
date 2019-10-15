#ifndef _BPF_EVENTS_H
#define _BPF_EVENTS_H

static inline void event_filename_builder(struct event_execve *event, void *pfilename)
{
	char *filename;

	probe_read(&filename, sizeof(filename), pfilename);
	if (filename)
		probe_read_str(event->filename, sizeof(event->filename), filename);
}

static inline void event_args_builder(struct event_execve *event, void *pargs)
{
	char **args;
	const unsigned int length = ARGSIZE;
	unsigned int offset = 0;

	probe_read(&args, sizeof(args), pargs);
	if (args) {
		unsigned int i = 0;
		bool done = 0;

#pragma clang loop unroll(full)
		for (i = 0; !done && i < 8; i++) {
			char *arg;
			int size = length - offset - 1;

			if (done)
				continue;
			probe_read(&arg, sizeof(arg), &args[i+1]);
			if (!arg) {
				done = 1;
				continue;
			}
			if (size > 0)
				offset += probe_read_str(&event->args[offset&ARGSMASK], size&ARGSSIZEMASK, arg);
		}

		event->args[offset&ARGSMASK] = 0x00;
	}
}
#endif // _BPF_EVENTS_H
