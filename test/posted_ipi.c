#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <sched.h>

#include "libdune/dune.h"
#include "libdune/cpu-x86.h"
#include "libdune/local.h"

#define NUM_THREADS 10
#define TEST_VECTOR 0xF2

static void test_handler(struct dune_tf *tf)
{
	printf("posted_ipi: received posted IPI on core %d\n", sched_getcpu());
	dune_apic_eoi();
	pthread_exit(NULL);
}

void *t_start(void *arg)
{
	volatile int ret = dune_enter();
	if (ret) {
		printf("posted_ipi: failed to enter dune in thread %d\n", sched_getcpu());
		return NULL;
	}
	dune_apic_init_rt_entry();
	dune_register_intr_handler(TEST_VECTOR, test_handler);
	asm volatile("mfence" ::: "memory");
	*(volatile bool *)arg = true;
	while (true);
	return NULL;
}

int main(int argc, char *argv[])
{
	volatile int ret;
	cpu_set_t cpus;
	pthread_t pthreads[NUM_THREADS];
	volatile bool ready[NUM_THREADS];
	int i;
	pthread_attr_t attr;

	CPU_ZERO(&cpus);
	CPU_SET(NUM_THREADS, &cpus);
	if (pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpus) != 0 ||
		sched_getcpu() != NUM_THREADS) {
		printf("Could not pin thread to core %d.\n", NUM_THREADS);
		return 1;
	} else {
		printf("Thread pinned to core %d.\n", NUM_THREADS);
	}

	printf("posted_ipi: not running dune yet\n");

	ret = dune_init_and_enter();
	if (ret) {
		printf("failed to initialize dune\n");
		return ret;
	}
	printf("posted_ipi: now printing from dune mode on core %d\n", sched_getcpu());
	dune_apic_init_rt_entry();

	for (i = 0; i < NUM_THREADS; i++) {
		ready[i] = false;

		pthread_attr_init(&attr);
		CPU_ZERO(&cpus);
		CPU_SET(i, &cpus);
		pthread_attr_setaffinity_np(&attr, sizeof(cpu_set_t), &cpus);
		pthread_create(&pthreads[i], &attr, t_start, (void *)&ready[i]);
	}

	for (i = 0; i < NUM_THREADS; i++) {
		while (!ready[i]);
	}
	asm volatile("mfence" ::: "memory");

	printf("About to send posted IPIs to %d cores\n", NUM_THREADS);

	for (i = 0; i < NUM_THREADS; i++) {
		dune_apic_send_ipi(TEST_VECTOR, dune_apic_id_for_cpu(i, NULL));
	}
	for (i = 0; i < NUM_THREADS; i++) {
		pthread_join(pthreads[i], NULL);
	}

	return 0;
}
