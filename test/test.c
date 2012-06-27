#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <err.h>

#include "libdune/dune.h"

static int check_dune(void)
{
	dune_flush_tlb();

	return 0;
}

static int test_fork(void)
{
	int pid;
	int rc;

	if (dune_init())
		return 1;

	if (check_dune())
		return 2;
/*
	pid = fork();
	if (pid == -1)
		return 3;
*/

	asm ("mov $57, %%rax\n"
	     "vmcall\n" 
	     :  "=A" (pid)
	     :
	     : 
	     );

	/* child */
	if (pid == 0) {
//		if (check_dune())
//			exit(1);

		sleep(5);

		exit(0);
	} else {
		if (check_dune())
			return 4;

		if (waitpid(pid, &rc, 0) == -1)
			err(5, "waitpid()");

		if (WEXITSTATUS(rc))
			return 6;
	}

	return 0;
}

static struct test {
	char	*name;
	int	(*cb)(void);
} _tests[] = {
	{ "fork", test_fork },
};

static void run_test(struct test *t)
{
	int rc;
	int pid;

	printf("==== Running test %s\n", t->name);

	pid = fork();
	if (pid == -1)
		err(1, "fork()");

	/* child */
	if (pid == 0) {
		rc = t->cb();
		exit(rc);
	}

	if (waitpid(pid, &rc, 0) == -1)
		err(1, "waitpid()");

	rc = WEXITSTATUS(rc);

	printf("==== Test %s - %s", t->name, rc ? "FAILED" : "passed" );
	if (rc)
		printf(" rc %d\n", rc);
	else
		printf("\n");
}

int main(int argc, char *argv[])
{
	int i;

	printf("Doing tests\n");

	for (i = 0; i < sizeof(_tests) / sizeof(*_tests); i++)
		run_test(&_tests[i]);

	printf("Done all tests\n");
	exit(0);
}
