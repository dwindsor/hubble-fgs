#ifndef _BPF_EVENTS_H
#define _BPF_EVENTS_H

static inline void event_filename_builder(struct event_execve *event, void *pfilename)
{
	char *filename;

	memset(event->filename, 0, sizeof(event->filename));
	probe_read(&filename, sizeof(filename), pfilename);
	if (filename)
		probe_read_str(event->filename, sizeof(event->filename), filename);
}

static inline void event_args_builder(struct event_execve *event, void *pargs)
{
	char **args;

	probe_read(&args, sizeof(args), pargs);
	if (args) {
		unsigned int i = 0;
#pragma unroll
		for (i = 0; i < MAXARGS; i++) {
			char *arg;

			probe_read(&arg, sizeof(arg), &args[i+1]);
			if (!arg)
				break;
			memset(&event->args[i], 0, sizeof(event->args[i]));
			probe_read_str(&event->args[i], sizeof(event->args[i]), arg);
		}
	}
}
#endif // _BPF_EVENTS_H
