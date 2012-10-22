#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <err.h>

#define NUM_THREADS	5

static int _threads_survived = 0;

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

int main(int argc, char *argv[])
{
	test_thread_memory();
	exit(0);
}
