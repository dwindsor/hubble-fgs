// Example taken from: https://man7.org/linux/man-pages/man3/dlopen.3.html
// Compile with: gcc dlopen.c -o dlopen -ldl
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>

int main(void)
{
	void *handle;
	double (*cosine)(double);
	char *error;

	handle = dlopen("/lib/x86_64-linux-gnu/libm.so.6", RTLD_LAZY);
	if (!handle) {
		fprintf(stderr, "%s\n", dlerror());
		exit(EXIT_FAILURE);
	}

	dlerror(); /* Clear any existing error */

	cosine = (double (*)(double))dlsym(handle, "cos");

	error = dlerror();
	if (error != NULL) {
		fprintf(stderr, "%s\n", error);
		exit(EXIT_FAILURE);
	}

	printf("%f\n", (*cosine)(2.0));
	dlclose(handle);

	exit(EXIT_SUCCESS);
}