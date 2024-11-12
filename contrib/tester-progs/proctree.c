#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <wait.h>

int main(int argc, char *argv[])
{
	char sleepbin[] = "/bin/sleep";
	char sleeptime[] = "1";
	char children[15];
	int num_children;
	char *args[3];
	int status;
	pid_t pid;

	if (argc < 2) {
		printf("%s <num_children>\n", argv[0]);
		exit(1);
	}

	num_children = atoi(argv[1]);

	if (num_children) {
		pid = fork();
		if (pid < 0) {
			printf("fork failed: %s\n", strerror(errno));
			exit(1);
		} else if (pid > 0) {
			// parent
			if (num_children > 0) {
				wait(&status);
				sleep(300);
			}
			sleep(1);
			exit(0);
		}

		// child
		args[0] = argv[0];
		args[1] = children;
		args[2] = 0;
		if (num_children > 0)
			num_children = - num_children;
		sprintf(children, "%d", num_children + 1);
		execve(argv[0], args, 0);
	}

	// num_children == 0
	// wait for the process cache to reap the exited parents
	sleep(3);
	// now exec and see what the ancestors are
	args[0] = sleepbin;
	args[1] = sleeptime;
	args[2] = 0;
	execve(args[0], args, 0);

	return 0;
}

