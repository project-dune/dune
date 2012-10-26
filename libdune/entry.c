/*
 * entry.c - Handles transition into dune mode
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <sys/mman.h>
#include <errno.h>
#include <malloc.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <asm/prctl.h>
#include <string.h>
#include <sys/ioctl.h>
#include <err.h>
#include <signal.h>
#include <pthread.h>

#include "../kern/dune.h"
#include "dune.h"
#include "mmu.h"
#include "cpu-x86.h"
#include "local.h"

ptent_t *pgroot;
uintptr_t mmap_base;
uintptr_t stack_base;
static struct dune_percpu *_percpu;

static int dune_fd;

static struct idtd idt[IDT_ENTRIES];

static uint64_t gdt_template[NR_GDT_ENTRIES] = {
	0,
	0,
	SEG64(SEG_X | SEG_R, 0),
	SEG64(SEG_W, 0),
	0,
	SEG64(SEG_W, 3),
	SEG64(SEG_X | SEG_R, 3),
	0,
	0,
};

struct dune_percpu {
	uint64_t tmp;
	uint64_t kfs_base;
	uint64_t ufs_base;
	uint64_t in_usermode;
	struct Tss tss;
	uint64_t gdt[NR_GDT_ENTRIES];
} __attribute__((packed));

unsigned long dune_get_user_fs(void)
{
	void *ptr;
	asm("movq %%gs:%c[ufs_base], %0" : "=r"(ptr) :
	    [ufs_base]"i"(offsetof(struct dune_percpu, ufs_base)) : "memory");
	return (unsigned long) ptr;
}

void dune_set_user_fs(unsigned long fs_base)
{
	asm ("movq %0, %%gs:%c[ufs_base]" : : "r"(fs_base),
	     [ufs_base]"i"(offsetof(struct dune_percpu, ufs_base)));
}

static void map_ptr(void *p, int len)
{
	unsigned long page = PGADDR(p);
	unsigned long page_end = PGADDR((char*) p + len);
	unsigned long l = (page_end - page) + PGSIZE;
	void *pg = (void*) page;

	dune_vm_map_phys(pgroot, pg, l, (void*) dune_va_to_pa(pg),
			 PERM_R | PERM_W);
}

static int setup_safe_stack(struct dune_percpu *percpu)
{
	int i;
	char *safe_stack;

	safe_stack = mmap(NULL, PGSIZE, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	if (safe_stack == MAP_FAILED)
		return -ENOMEM;

	map_ptr(safe_stack, PGSIZE);

	safe_stack += PGSIZE;
	percpu->tss.tss_iomb = offsetof(struct Tss, tss_iopb);

	for (i = 1; i < 8; i++)
		percpu->tss.tss_ist[i] = (uintptr_t) safe_stack;

	/* changed later on jump to G3 */
	percpu->tss.tss_rsp[0] = (uintptr_t) safe_stack;

	return 0;
}

static void setup_gdt(struct dune_percpu *percpu)
{	
	memcpy(percpu->gdt, gdt_template, sizeof(uint64_t) * NR_GDT_ENTRIES);

	percpu->gdt[GD_TSS >> 3] = (SEG_TSSA | SEG_P | SEG_A |
				    SEG_BASELO(&percpu->tss) |
				    SEG_LIM(sizeof(struct Tss) - 1));
	percpu->gdt[GD_TSS2 >> 3] = SEG_BASEHI(&percpu->tss);
}

static void __dune_boot(struct dune_percpu *percpu)
{
	struct tptr _idtr, _gdtr;

	_gdtr.base  = (uint64_t) &percpu->gdt;
	_gdtr.limit = sizeof(percpu->gdt) - 1;

	_idtr.base = (uint64_t) &idt;
	_idtr.limit = sizeof(idt) - 1;

	asm volatile (
		// STEP 1: load the new GDT
		"lgdt %0\n"

		// STEP 2: initialize data segements
		"mov $" __str(GD_KD) ", %%ax\n"
		"mov %%ax, %%ds\n"
		"mov %%ax, %%es\n"
		"mov %%ax, %%ss\n"

		// STEP 3: long jump into the new code segment
		"mov $" __str(GD_KT) ", %%rax\n"
		"pushq %%rax\n"
		"pushq $.flush\n"
		"lretq\n"
		".flush:\n"
		"nop\n"

		// STEP 4: load the task register (for safe stack switching)
		"mov $" __str(GD_TSS) ", %%ax\n"
		"ltr %%ax\n"

		// STEP 5: load the new IDT and enable interrupts
		"lidt %1\n"
		"sti\n"

		: : "m" (_gdtr), "m" (_idtr) : "rax");
	
	// STEP 6: FS and GS require special initialization on 64-bit
	wrmsrl(MSR_FS_BASE, percpu->kfs_base);
	wrmsrl(MSR_GS_BASE, (unsigned long) percpu);
}

/**
 * dune_boot - Brings the user-level OS online
 */
static int dune_boot(struct dune_percpu *percpu)
{
	setup_gdt(percpu);
	__dune_boot(percpu);

	return 0;
}

#define ISR_LEN 16

static inline void set_idt_addr(struct idtd *id, physaddr_t addr)
{       
        id->low    = addr & 0xFFFF;
        id->middle = (addr >> 16) & 0xFFFF;
        id->high   = (addr >> 32) & 0xFFFFFFFF;
}

static void setup_idt(void)
{
	int i;

	for (i = 0; i < IDT_ENTRIES; i++) {
		struct idtd *id = &idt[i];
		uintptr_t isr = (uintptr_t) &__dune_intr;

		isr += ISR_LEN * i;
		memset(id, 0, sizeof(*id));
                
		id->selector = GD_KT;
		id->type     = IDTD_P | IDTD_TRAP_GATE;
		if (i == T_BRKPT)
			id->type |= IDTD_CPL3;
		if (i == T_BRKPT || i == T_DBLFLT || i == T_NMI || i == T_MCHK)
			id->ist = 1;

		set_idt_addr(id, isr);
	}
}

static int setup_syscall(void)
{
	unsigned long lstar;
	unsigned long lstara;
	unsigned char *page;
	ptent_t *pte;
	size_t off;
	int i;

	assert((unsigned long) __dune_syscall_end  -
	       (unsigned long) __dune_syscall < PGSIZE);

	lstar = ioctl(dune_fd, DUNE_GET_SYSCALL);
	if (lstar == -1)
		return -errno;

	page = mmap((void *) NULL, PGSIZE * 2,
		    PROT_READ | PROT_WRITE | PROT_EXEC,
		    MAP_PRIVATE | MAP_ANON, -1, 0);

	if (page == MAP_FAILED)
		return -errno;

	lstara = lstar & ~(PGSIZE - 1);
	off = lstar - lstara;

	memcpy(page + off, __dune_syscall, 
		(unsigned long) __dune_syscall_end -
		(unsigned long) __dune_syscall);

	for (i = 0; i <= PGSIZE; i += PGSIZE) {
		uintptr_t pa = dune_mmap_addr_to_pa(page + i);
		dune_vm_lookup(pgroot, (void *) (lstara + i), 1, &pte);
		*pte = PTE_ADDR(pa) | PTE_P;
	}
	
	return 0;
}

#define VSYSCALL_ADDR 0xffffffffff600000

static void setup_vsyscall(void)
{
	ptent_t *pte;

	dune_vm_lookup(pgroot, (void *) VSYSCALL_ADDR, 1, &pte);
	*pte = PTE_ADDR(dune_va_to_pa(&__dune_vsyscall_page)) | PTE_P | PTE_U;
}

static void __setup_mappings_cb(const struct dune_procmap_entry *ent)
{
	int perm = PERM_NONE;
	int ret;

	// page region already mapped
	if (ent->begin == (unsigned long) PAGEBASE)
		return;
	
	if (ent->begin == (unsigned long) VSYSCALL_ADDR) {
		setup_vsyscall();
		return;
	}

	if (ent->r)
		perm |= PERM_R;
	if (ent->w)
		perm |= PERM_W;
	if (ent->x)
		perm |= PERM_X;

	ret = dune_vm_map_phys(pgroot, (void *) ent->begin,
			      ent->end - ent->begin,
			      (void *) dune_va_to_pa((void *) ent->begin),
			      perm);
	assert(!ret);
}

static int __setup_mappings_precise(void)
{
	int ret;

	ret = dune_vm_map_phys(pgroot, (void *) PAGEBASE,
			      MAX_PAGES * PGSIZE,
			      (void *) dune_va_to_pa((void *) PAGEBASE),
			      PERM_R | PERM_W | PERM_BIG);
	if (ret)
		return ret;

	dune_procmap_iterate(&__setup_mappings_cb);

	return 0;
}

static int __setup_mappings_full(struct dune_layout *layout)
{
	int ret;

	ret = dune_vm_map_phys(pgroot, (void *) layout->base_proc, GPA_SIZE,
			      (void *) GPA_ADDR_PROC,
			      PERM_R | PERM_W | PERM_X | PERM_U);
	if (ret)
		return ret;

	ret = dune_vm_map_phys(pgroot, (void *) layout->base_map, GPA_SIZE,
			      (void *) GPA_ADDR_MAP,
			      PERM_R | PERM_W | PERM_X | PERM_U);
	if (ret)
		return ret;

	ret = dune_vm_map_phys(pgroot, (void *) layout->base_stack, GPA_SIZE,
			      (void *) GPA_ADDR_STACK,
			      PERM_R | PERM_W | PERM_X | PERM_U);
	if (ret)
		return ret;

	setup_vsyscall();

	return 0;
}

static int setup_mappings(bool full)
{
	struct dune_layout layout;
	int ret = ioctl(dune_fd, DUNE_GET_LAYOUT, &layout);
	if (ret)
		return ret;

	mmap_base = layout.base_map;
	stack_base = layout.base_stack;

	if (full)
		ret = __setup_mappings_full(&layout);
	else
		ret = __setup_mappings_precise();

	return ret;
}

struct dune_percpu *setup_percpu(void)
{
	struct dune_percpu *percpu;
	int ret;
	unsigned long fs_base;

	if (arch_prctl(ARCH_GET_FS, &fs_base) == -1) {
		printf("dune: failed to get FS register\n");
		return NULL;
	}

	percpu = mmap(NULL, PGSIZE, PROT_READ | PROT_WRITE,
		      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (percpu == MAP_FAILED)
		return NULL;

	map_ptr(percpu, sizeof(*percpu));

        percpu->kfs_base = fs_base;
	percpu->ufs_base = fs_base;
	percpu->in_usermode = 0;

	if ((ret = setup_safe_stack(percpu))) {
		munmap(percpu, PGSIZE);
		return NULL;
	}

	setup_gdt(percpu);

	return percpu;
}

static void free_percpu(struct dune_percpu *percpu)
{
	/* XXX free stack */
	munmap(percpu, PGSIZE);
}

/**
 * dune_enter - transitions a process to "Dune mode"
 * 
 * Must be called within each forked child and/or each new thread
 * if you want to remain in "Dune mode".
 * 
 * Returns 0 on success, otherwise failure.
 */
int dune_enter(void)
{
	struct dune_percpu *percpu = NULL;
	struct dune_config conf;
	uint64_t arch_fs;
	int ret;
	int frk = 0;

	if (arch_prctl(ARCH_GET_FS, &arch_fs) == -1) {
		printf("dune: failed to get FS register\n");
		return -errno;
	}

	if (arch_fs == _percpu->kfs_base) {
		frk    = 1;
		percpu = _percpu;
	} else
		percpu = setup_percpu();

	conf.rip = (__u64) &__dune_ret;
	conf.rsp = 0;
	conf.cr3 = (physaddr_t) pgroot;

	ret = __dune_enter(dune_fd, &conf);
	if (ret) {
		printf("dune: entry to Dune mode failed\n");
		goto fail_enter;
	}

	ret = dune_boot(percpu);
	if (ret) {
		printf("dune: problem while booting, unrecoverable\n");
		dune_die();
	}

	return 0;

fail_enter:
	if (!frk)
		free_percpu(percpu);
	return ret;
}

/**
 * dune_init - initializes libdune
 * 
 * @map_full: determines if the full process address space should be mapped
 * 
 * Call this function once before using libdune.
 * 
 * Full mappings are typically used for testing and debugging. When
 * disabled, a much more efficient approach where only address ranges
 * mapped into memory are reflected in the guest page table. However,
 * this introduces an additional challenge in that any changes to
 * the process address space require an update to the page table.
 * 
 * Returns 0 on success, otherwise failure.
 */
int dune_init(bool map_full)
{
	int ret, i;

	dune_fd = open("/dev/dune", O_RDWR);
	if (dune_fd <= 0) {
		printf("dune: failed to open Dune device\n");
		ret = -errno;
		goto fail_open;
	}

	pgroot = memalign(PGSIZE, PGSIZE);
	if (!pgroot) {
		ret = -ENOMEM;
		goto fail_pgroot;
	}
	memset(pgroot, 0, PGSIZE);

	if ((ret = dune_page_init())) {
		printf("dune: unable to initialize page manager\n");
		goto err;
	}

	if ((ret = setup_mappings(map_full))) {
		printf("dune: unable to setup memory layout\n");
		goto err;
	}

	if ((ret = setup_syscall())) {
		printf("dune: unable to setup system calls\n");
		goto err;
	}

	// disable signals for now until we have better support
	for (i = 1; i < 32; i++) {
		struct sigaction sa;

		switch (i) {
		case SIGSTOP:
		case SIGKILL:
		case SIGCHLD:
			continue;
		}

		memset(&sa, 0, sizeof(sa));

		sa.sa_handler = SIG_IGN;

		if (sigaction(i, &sa, NULL) == -1)
			err(1, "sigaction() %d", i);
	}

	setup_idt();

	if (!(_percpu = setup_percpu())) {
		ret = -1;
		goto err;
	}

	return 0;

err:
	// FIXME: need to free memory
fail_pgroot:
	close(dune_fd);
fail_open:
	return ret;
}

