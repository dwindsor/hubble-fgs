#define _XOPEN_SOURCE 700

#include <unistd.h>
#include <stdio.h>
#include <signal.h>
#include <stdbool.h>
#include <time.h>

#define DURATION 60

bool done = false;

static void handler(int signum)
{
	if (signum == SIGALRM || signum == SIGINT) {
		done = true;
	}
}

int main(int argc, char **argv)
{
	double result, duration;
	struct timespec start, end;
	unsigned long n_calls = 0;
	struct sigaction sa;

	sa.sa_handler = handler;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGALRM, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);

	fprintf(stderr, "Running for %d seconds or until CTRL-C...\n", DURATION);
	alarm(DURATION);

	clock_gettime(CLOCK_MONOTONIC, &start);
	while (!done) {
		getpid();
		n_calls++;
	}
	clock_gettime(CLOCK_MONOTONIC, &end);
	duration = (end.tv_sec + (end.tv_nsec / 1000000000.0)) - (start.tv_sec + (start.tv_nsec / 1000000000.0));

	result = (double)n_calls / duration;
	printf("syscalls per second: %.2f\n", result);

	return 0;
}