#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>

#include "libdune/dune.h"

static uintptr_t fltaddr;

static void handler(uintptr_t addr, uint64_t fec, struct dune_tf *tf)
{
	// TODO: causes a crash -- does printf allocate too much stack space?
	printf("in fault handler: %lx\n", addr);

	fltaddr = addr;
	ptent_t *pte;
	dune_vm_lookup(pgroot, (void *)addr, 0, &pte);
	*pte |= PTE_W;
}

int main()
{
	if (dune_init_and_enter()) {
		printf("failed to initialize dune\n");
		return 1;
	}

	const int page_size = 4096;

	dune_register_pgflt_handler(handler);

	void *pg = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
					MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (!pg) {
		printf("mmap failed\n");
		return 1;
	}

	dune_vm_map_pages(pgroot, pg, page_size, PERM_R);

	char *page = (char *)pg;
	page[5] = 42;

	printf("page faulted at addr: %lx\n", fltaddr);

	return 0;
}
