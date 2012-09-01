/*
 * bench.h - shared definitions for all benchmarks
 */

#define NRPGS	100
#define N	10000

static inline void synch_tsc(void)
{
	asm volatile("cpuid" : : : "%rax", "%rbx", "%rcx", "%rdx");
}

static inline unsigned long rdtscll(void)
{
	unsigned int a, d;
	asm volatile("rdtsc" : "=a" (a), "=d" (d) : : "%rbx", "%rcx");
	return ((unsigned long) a) | (((unsigned long) d) << 32);
}

static inline unsigned long rdtscllp(void)
{
	unsigned int a, d;
	asm volatile("rdtscp" : "=a" (a), "=d" (d) : : "%rbx", "%rcx");
	return ((unsigned long) a) | (((unsigned long) d) << 32);
}

static unsigned long measure_tsc_overhead(void)
{
	unsigned long t0, t1, overhead = ~0UL;
	int i;

	for (i = 0; i < N; i++) {
		t0 = rdtscll();
		asm volatile("");
		t1 = rdtscllp();
		if (t1 - t0 < overhead)
			overhead = t1 - t0;
	}

	return overhead;
}
