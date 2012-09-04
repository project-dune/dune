#define _GNU_SOURCE

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "bench.h"

static char *mem;
unsigned long tsc, trap_tsc, overhead;
unsigned long time = 0;

#define PGSIZE	4096

static void prime_memory(void)
{
	int i;

	for (i = 0; i < NRPGS * 2; i++) {
		mem[i * PGSIZE] = i;
	}
}

static void benchmark1_handler(int sn, siginfo_t *si, void *ctx)
{
//	fprintf (stderr, "afault_handler: %x\n", si->si_addr);
	unsigned long addr = (((unsigned long) si->si_addr) & ~(PGSIZE - 1));
	time += rdtscllp() - trap_tsc;

	mprotect((void *) addr, PGSIZE, PROT_READ | PROT_WRITE);
	mprotect((void *) addr + PGSIZE * NRPGS, PGSIZE, PROT_READ);
}

static void benchmark1(void)
{
	int i;

	for (i = 0; i < NRPGS; i++) {
		trap_tsc = rdtscll();
		mem[i * PGSIZE] = i;
	}
}

static void benchmark2_handler(int sn, siginfo_t *si, void *ctx)
{
//	fprintf (stderr, "bfault_handler: %x\n", si->si_addr);
	unsigned long addr = (((unsigned long) si->si_addr) & ~(PGSIZE - 1));
	mprotect((void *) addr, PGSIZE, PROT_READ | PROT_WRITE);
}

static void benchmark2(void)
{
	int i;

	mprotect(mem, NRPGS * PGSIZE, PROT_READ);

	for (i = 0; i < NRPGS; i++) {
		mem[i * PGSIZE] = i;
	}
}

static void benchmark_syscall(void)
{
	int i;
	unsigned long t0;

	synch_tsc();
	t0 = rdtscll();
	for (i = 0; i < N; i++) {
		syscall(SYS_gettid);
	}

	printf("System call took %ld cycles\n", (rdtscllp() - t0 - overhead) / N);
}

void benchmark_fault(void)
{
	int i;
	unsigned long ticks;
	char *fm = mmap(NULL, N * PGSIZE, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	synch_tsc();
	ticks = rdtscll();
	for (i = 0; i < N; i++) {
		fm[i * PGSIZE] = i;
	}

	printf("Kernel fault took %ld cycles\n", (rdtscllp() - ticks - overhead) / N);
}

static void benchmark_appel1(void)
{
	struct sigaction act;
	int i;
	unsigned long avg_appel1 = 0, avg_user_fault = 0;

	memset(&act, sizeof(sigaction), 0);
	act.sa_sigaction = benchmark1_handler;
	act.sa_flags = SA_SIGINFO;
	sigemptyset(&act.sa_mask);
	sigaction(SIGSEGV, &act, NULL);

	for (i = 0; i < N; i++) {
		time = 0;
		mprotect(mem, NRPGS * PGSIZE, PROT_READ);
		synch_tsc();
		tsc = rdtscll();
		benchmark1();

		avg_appel1 += rdtscllp() - tsc - overhead;
		avg_user_fault += (time - overhead * NRPGS) / NRPGS;
	}

	printf("User fault took %ld cycles\n", avg_user_fault / N);
	printf("PROT1,TRAP,UNPROT took %ld cycles\n", avg_appel1 / N);
}

static void benchmark_appel2(void)
{
	struct sigaction act;
	int i;
	unsigned long avg = 0;

	memset(&act, sizeof(sigaction), 0);
	act.sa_sigaction = benchmark2_handler;
	act.sa_flags = SA_SIGINFO;
	sigemptyset(&act.sa_mask);
	sigaction(SIGSEGV, &act, NULL);

	for (i = 0; i < N; i++) {
		mprotect(mem, NRPGS * PGSIZE * 2, PROT_READ | PROT_WRITE);
		prime_memory();

		synch_tsc();
		tsc = rdtscll();
		benchmark2();
		avg += rdtscllp() - tsc - overhead;
	}

	printf("PROTN,TRAP,UNPROT took %ld cycles\n", avg / N);
}

int main(int argc, char *argv[])
{	
	overhead = measure_tsc_overhead();
	printf("TSC overhead is %ld\n", overhead);

	printf("Benchmarking Linux performance...\n");

	benchmark_syscall();
	benchmark_fault();
	
	mem = mmap(NULL, NRPGS * PGSIZE * 2, PROT_READ | PROT_WRITE,
		   MAP_PRIVATE | MAP_ANONYMOUS,
		   -1, 0);

	if (mem == (void *) -1)
		return -1;

	prime_memory();
	benchmark_appel1();
	benchmark_appel2();

	return 0;
}
