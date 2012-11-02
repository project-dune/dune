#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <err.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <asm/prctl.h>
#include <sys/prctl.h>

#define NUM_THREADS	10

extern int arch_prctl(int code, unsigned long *addr);

static int _threads_survived = 0;
static unsigned long _tls;

static void *xmalloc(size_t sz)
{
	void *x = malloc(sz);

	if (!x)
		err(1, "malloc()");

	return x;
}

static void *do_test_thread_memory(void *arg)
{
	int times = 10000;
	int i;
	char **ptrs;

	ptrs = xmalloc(sizeof(*ptrs) * times);

	for (i = 0; i < times; i++) {
		ptrs[i] = xmalloc(4096);

		if (ptrs[i][0])
			ptrs[i][1] = 2;
	}

	for (i = 0; i < times; i++)
		free(ptrs[i]);

	_threads_survived++;

	return NULL;
}

static void test_thread_memory(void)
{
	pthread_t pt[NUM_THREADS];
	int i;

	printf("=========== test_thread_memory\n");

	for (i = 0; i < NUM_THREADS; i++) {
		if (pthread_create(&pt[i], NULL, do_test_thread_memory, NULL))
			err(1, "pthread_create()");
	}

	for (i = 0; i < NUM_THREADS; i++) {
		if (pthread_join(pt[i], NULL))
			err(1, "pthread_join()");
	}

	if (_threads_survived == NUM_THREADS)
		printf("PASSED\n");
	else
		printf("FAILED\n");
}

static void *thread_pthread_fork(void *arg)
{
	pid_t pid;
	unsigned long tls = 0;

	_threads_survived++;

        if (arch_prctl(ARCH_GET_FS, &tls) == -1)
		err(1, "arch_prctl()");

	if (tls == _tls) {
		printf("FAILED\n");
		return NULL;
	}

	_tls = tls;

	if ((pid = fork()) == -1)
		err(1, "fork()");

	if (pid == 0) {
		_threads_survived++;
		
		tls = 0;
		if (arch_prctl(ARCH_GET_FS, &tls) == -1)
			err(1, "arch_prctl()");

		if (tls != _tls) {
			printf("FAILED\n");
			exit(0);
		}

		if (_threads_survived == 2)
			printf("PASSED\n");

		exit(0);
	} else
		wait(NULL);

	return NULL;
}

static void test_pthread_fork(void)
{
	pthread_t pt;

	printf("============ test_pthread_fork\n");

	_threads_survived = 0;
	arch_prctl(ARCH_GET_FS, &_tls);

	if (pthread_create(&pt, NULL, thread_pthread_fork, NULL))
		err(1, "pthread_create()");

	if (pthread_join(pt, NULL))
		err(1, "pthread_join()");
}

int main(int argc, char *argv[])
{
	test_thread_memory();
	test_pthread_fork();
	exit(0);
}
