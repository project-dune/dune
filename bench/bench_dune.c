#include <stdio.h>
#include <sys/mman.h>

#include "libdune/dune.h"

#define N		1000
#define NRPGS		100
#define MAP_ADDR	0x400000000000

static char *mem;
unsigned long trap_tsc;
unsigned long time = 0;

static void prime_memory(void)
{
	int i;

	for (i = 0; i < NRPGS * 2; i++) {
		mem[i * PGSIZE] = i;
	}
}

static void
benchmark1_handler(uintptr_t addr, uint64_t fec, struct dune_tf *tf)
{
	ptent_t *pte;
	int accessed;

	time += dune_get_ticks() - trap_tsc;

	dune_vm_lookup(pgroot, (void *) addr, 0, &pte);
	*pte |= PTE_P | PTE_W | PTE_U | PTE_A | PTE_D;

	dune_vm_lookup(pgroot, (void *) addr + NRPGS * PGSIZE, 0, &pte);
	accessed = *pte & PTE_A;
	*pte = PTE_ADDR(*pte);
	if (accessed)
		dune_flush_tlb_one(addr + NRPGS * PGSIZE);
}

static void benchmark1(void)
{
	int i;

	for (i = 0; i < NRPGS; i++) {
		trap_tsc = dune_get_ticks();
		mem[i * PGSIZE] = i;
	}
}

static void
benchmark2_handler(uintptr_t addr, uint64_t fec,  struct dune_tf *tf)
{
	ptent_t *pte;

	dune_vm_lookup(pgroot, (void *) addr, 0, &pte);
	*pte |= PTE_P | PTE_W | PTE_U | PTE_A | PTE_D;
}

static void benchmark2(void)
{
	int i;

	dune_vm_mprotect(pgroot, (void *) MAP_ADDR, PGSIZE * NRPGS, PERM_R);

	for (i = 0; i < NRPGS; i++) {
		mem[i * PGSIZE] = i;
	}
}

void benchmark_syscall(void)
{
	int i;
	unsigned long ticks = dune_get_ticks();

	for (i = 0; i < N; i++) {
		int ret;

		asm volatile("movq $39, %%rax \n\t" // get_pid
		"vmcall \n\t"
		"mov %%eax, %0 \n\t" :
		"=r" (ret) :: "rax");
	}

	dune_printf("System call took %ld cycles\n", (dune_get_ticks() - ticks) / N);
}

void benchmark_fault(void)
{
	int i;
	unsigned long ticks;
	char *fm = dune_mmap(NULL, N * PGSIZE, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	ticks = dune_get_ticks();
	for (i = 0; i < N; i++) {
		fm[i * PGSIZE] = i;
	}

	dune_printf("Kernel fault took %ld cycles\n", (dune_get_ticks() - ticks) / N);
}

int main(int argc, char *argv[])
{
	int ret;
	unsigned long tsc;

	ret = dune_init_and_enter();
	if (ret) {
		printf("failed to initialize dune\n");
		return ret;
	}

	dune_printf("Benchmarking dune performance...\n");

	benchmark_syscall();
	benchmark_fault();

	ret = dune_vm_map_pages(pgroot,
                           (void *) MAP_ADDR,
			               2 * NRPGS * PGSIZE,
			               PERM_R | PERM_W);
	if (ret) {
		printf("failed to setup memory mapping\n");
		return ret;
	}

	mem = (void *) MAP_ADDR;

	dune_register_pgflt_handler(benchmark1_handler);
	prime_memory();
	dune_vm_mprotect(pgroot, (void *) MAP_ADDR, PGSIZE * NRPGS, PERM_R);

	tsc = dune_get_ticks();
	benchmark1();
	dune_printf("User fault took %ld cycles\n", time / NRPGS);
	dune_printf("PROT1,TRAP,UNPROT took %ld cycles\n", dune_get_ticks() - tsc);

	dune_register_pgflt_handler(benchmark2_handler);
	dune_vm_mprotect(pgroot, (void *) MAP_ADDR,
                    PGSIZE * NRPGS * 2, PERM_R | PERM_W);
	prime_memory();

	tsc = dune_get_ticks();
	benchmark2();
	dune_printf("PROTN,TRAP,UNPROT took %ld cycles\n", dune_get_ticks() - tsc);
	
	return 0;
}
