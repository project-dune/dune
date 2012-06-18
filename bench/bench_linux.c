#define _GNU_SOURCE

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

static char *mem;
unsigned long tsc, trap_tsc;
unsigned long time = 0;

#define PGSIZE	4096
#define NRPGS	100

static inline unsigned long rdtscll(void)
{
	unsigned int a, d;
	asm volatile("rdtsc" : "=a" (a), "=d" (d));
	return ((unsigned long) a) | (((unsigned long) d) << 32);
}

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
	time += rdtscll() - trap_tsc;

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

#define N	1000

static void benchmark_syscall(void)
{
	int i;
	unsigned long t0 = rdtscll();
	for (i = 0; i < N; i++) {
		syscall(SYS_gettid);
	}

	printf("System call took %ld cycles\n", (rdtscll() - t0) / N);
}

void benchmark_fault(void)
{
	int i;
	unsigned long ticks;
	char *fm = mmap(NULL, N * PGSIZE, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	ticks = rdtscll();
	for (i = 0; i < N; i++) {
		fm[i * PGSIZE] = i;
	}

	printf("Kernel fault took %ld cycles\n", (rdtscll() - ticks) / N);
}

int main(int argc, char *argv[])
{	struct sigaction act;
	unsigned long tsc;

	printf("Benchmarking Linux performance...\n");

	benchmark_syscall();
	benchmark_fault();
	
	mem = mmap(NULL, NRPGS * PGSIZE * 2, PROT_READ | PROT_WRITE,
		   MAP_PRIVATE | MAP_ANONYMOUS,
		   -1, 0);

	if (mem == (void *) -1)
		return -1;

	prime_memory();
	memset(&act, sizeof(sigaction), 0);
	act.sa_sigaction = benchmark1_handler;
	act.sa_flags = SA_SIGINFO;
	sigemptyset(&act.sa_mask);
	sigaction(SIGSEGV, &act, NULL);
	mprotect(mem, NRPGS * PGSIZE, PROT_READ);

	tsc = rdtscll();
	benchmark1();
	printf("User fault took %ld cycles\n", (time) / NRPGS);
	printf("PROT1,TRAP,UNPROT took %ld cycles\n", rdtscll() - tsc);

	mprotect(mem, NRPGS * PGSIZE * 2, PROT_READ | PROT_WRITE);
	prime_memory();

	memset(&act, sizeof(sigaction), 0);
	act.sa_sigaction = benchmark2_handler;
	act.sa_flags = SA_SIGINFO;
	sigemptyset(&act.sa_mask);
	sigaction(SIGSEGV, &act, NULL);

	tsc = rdtscll();
	benchmark2();
	printf("PROTN,TRAP,UNPROT took %ld cycles\n", rdtscll() - tsc);

	return 0;
}
