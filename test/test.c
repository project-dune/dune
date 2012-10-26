#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <err.h>
#include <string.h>
#include <pthread.h>

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

	if (dune_enter())
		return 1;

	if (check_dune())
		return 2;

	pid = fork();
	if (pid == -1)
		return 3;

	/* child */
	if (pid == 0) {
		if (dune_enter())
			return 1;

		if (check_dune())
			exit(1);

		exit(69);
	} else {
		if (check_dune())
			return 4;

		if (waitpid(pid, &rc, 0) == -1)
			err(5, "waitpid()");

		if (WEXITSTATUS(rc) != 69)
			return 6;
	}

	return 255;
}

static void *test_pthread_thread(void *arg)
{
	if (dune_enter())
		return NULL;

	if (check_dune())
		return NULL;

	return (void*) 0x666;
}

static int test_pthread(void)
{
	pthread_t pt;
	void *ret;

	if (dune_enter())
		return 1;

	if (check_dune())
		return 2;

	if (pthread_create(&pt, NULL, test_pthread_thread, NULL))
		err(1, "pthread_create()");

	if (check_dune())
		return 3;

	if (pthread_join(pt, &ret))
		return 4;

	if (ret != (void*) 0x666)
		return 5;

	if (check_dune())
		return 6;

	return 255;
}

static int test_signal_glob = 0;

static void test_signal_handler(int num)
{
	test_signal_glob = 666;
}

static int test_signal(void)
{
	int pid;

	if (dune_enter())
		return 1;

	pid = getpid();

	if (dune_signal(SIGUSR1, test_signal_handler) == SIG_ERR)
		err(1, "signal()");

	if (kill(pid, SIGUSR1) == -1)
		err(1, "kill()");

	if (test_signal_glob != 666)
		return 2;

	return 255; 
}

static struct test {
	char	*name;
	int	(*cb)(void);
} _tests[] = {
	{ "fork", test_fork },
	{ "pthread", test_pthread },
	{ "signal", test_signal },
};

static void run_test(struct test *t)
{
	int rc, status;
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

	if (waitpid(pid, &status, 0) == -1)
		err(1, "waitpid()");

	rc = WEXITSTATUS(status);

	printf("==== Test %s - %s", t->name, rc != 255 ? "FAILED" : "passed" );

	if (WIFSIGNALED(status))
		printf(" [crashed]");

	if (rc != 255)
		printf(" rc %d\n", rc);
	else
		printf("\n");
}

int main(int argc, char *argv[])
{
	int i, ret;

	ret = dune_init_and_enter();
	if (ret) {
		printf("failed to initialize dune\n");
		return ret;
	}

	printf("Doing tests\n");

	for (i = 0; i < sizeof(_tests) / sizeof(*_tests); i++)
		run_test(&_tests[i]);

	printf("Done all tests\n");
	exit(0);
}
