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

#include "../kern/dune.h"
#include "dune.h"
#include "mmu.h"
#include "cpu-x86.h"

extern int arch_prctl(int code, unsigned long *addr);
extern int dune_page_init(void);

// these are assembly routines from dune.S
extern int __dune_enter(int fd, struct dune_config *config);
extern int __dune_ret(void);
extern void __dune_syscall(void);
extern void __dune_syscall_end(void);
extern void __dune_intr(void);

#define ISR_LEN 16

#define __str_t(x...)	#x
#define __str(x...)	__str_t(x)

#define PHYSICAL_ADDR_BITS ((__u64) 1 << 36)

 ptent_t *pgroot;
static uint64_t arch_fs;
uintptr_t mmap_base;
uintptr_t stack_base;

struct dune_percpu {
	uint64_t tmp;
	uint64_t kfs_base;
	uint64_t ufs_base;
	struct Tss tss;
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

static uint64_t gdt[9] = {
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

static struct idtd idt[IDT_ENTRIES];

static int setup_safe_stack(struct dune_percpu *percpu)
{
	int i;
	struct page *p = dune_page_alloc();
	if (!p)
		return -ENOMEM;

	for (i = 1; i < 8; i++)
		percpu->tss.tss_ist[i] = dune_page2pa(p) + PGSIZE;

	/* setup later on jump to G3 */
	percpu->tss.tss_rsp[0] = dune_page2pa(p) + PGSIZE;

	return 0;
}

static void setup_gdt(struct dune_percpu *percpu)
{
	struct tptr _gdtr;

	_gdtr.base  = (uint64_t) &gdt;
	_gdtr.limit = sizeof(gdt) - 1;

	gdt[GD_TSS >> 3] = (SEG_TSSA | SEG_P | SEG_A |
			    SEG_BASELO(&percpu->tss) |
			    SEG_LIM(sizeof(struct Tss) - 1));
	gdt[GD_TSS2 >> 3] = SEG_BASEHI(&percpu->tss);

	percpu->tss.tss_iomb = offsetof(struct Tss, tss_iopb);
	setup_safe_stack(percpu);

	asm volatile (
		"lgdt %0\n"

		/* data */
		"mov $" __str(GD_KD) ", %%ax\n"
		"mov %%ax, %%ds\n"
		"mov %%ax, %%es\n"
		"mov %%ax, %%gs\n"
		"mov %%ax, %%ss\n"

		// NOTE: fs.base and gs.base is set by MSR on x86_64

		/* text */
		"mov $" __str(GD_KT) ", %%rax\n"
		"pushq %%rax\n"
		"pushq $.flush\n"
		"lretq\n"
		".flush:\n"
		"nop\n"

		/* task register */
		"mov $" __str(GD_TSS) ", %%ax\n"
		"ltr %%ax\n"

		: : "m" (_gdtr) : "rax");

	wrmsrl(MSR_FS_BASE, arch_fs);
	wrmsrl(MSR_GS_BASE, (unsigned long) percpu);

}

static inline void set_idt_addr(struct idtd *id, physaddr_t addr)
{       
        id->low    = addr & 0xFFFF;
        id->middle = (addr >> 16) & 0xFFFF;
        id->high   = (addr >> 32) & 0xFFFFFFFF;
}

static void setup_idt(void)
{
	struct tptr _idtr;
	int i;
	
	_idtr.base = (uint64_t) &idt;
	_idtr.limit = sizeof(idt) - 1;

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

	asm volatile (
		"lidt %0\n"
		"sti\n"
		: : "m" (_idtr));
}

/**
 * dune_boot - Brings the user-level OS online
 */
static void dune_boot(struct dune_percpu *percpu)
{
	setup_gdt(percpu);
	setup_idt();
}

static void setup_syscall(int dune_fd)
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
		err(1, "ioctl(DUNE_GET_SYSCALL)");

	page = mmap((void *) NULL, PGSIZE * 2,
		    PROT_READ | PROT_WRITE | PROT_EXEC,
		    MAP_PRIVATE | MAP_ANON, -1, 0);

	if (page == MAP_FAILED)
		err(1, "mmap()");

	lstara = lstar & ~(PGSIZE - 1);
	off = lstar - lstara;

	memcpy(page + off, __dune_syscall, 
		(unsigned long) __dune_syscall_end - (unsigned long)
		__dune_syscall);

	for (i = 0; i <= PGSIZE; i += PGSIZE) {
		uintptr_t pa = dune_mmap_addr_to_pa(page + i);
		dune_vm_lookup(pgroot, (void *) (lstara + i), 1, &pte);
		*pte = PTE_ADDR(pa) | PTE_P;
	}
}

static void procmap_cb(const struct dune_procmap_entry *ent)
{
	int perm = PERM_NONE;
	int ret;

	// page region already mapped
	if (ent->begin == (unsigned long) PAGEBASE)
		return;

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

static int setup_layout_fast(void)
{
	int ret;

	ret = dune_vm_map_phys(pgroot, (void *) PAGEBASE,
			      MAX_PAGES * PGSIZE,
			      (void *) dune_va_to_pa((void *) PAGEBASE),
			      PERM_R | PERM_W | PERM_BIG);
	if (ret)
		return ret;

	dune_procmap_iterate(&procmap_cb);

	return 0;
}

static int setup_layout_safe(struct dune_layout *layout)
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

	return 0;
}

static int setup_layout(int fd, bool safe)
{
	struct dune_layout layout;
	int ret = ioctl(fd, DUNE_GET_LAYOUT, &layout);
	if (ret)
		return ret;

	mmap_base = layout.base_map;
	stack_base = layout.base_stack;

	if (safe)
		ret = setup_layout_safe(&layout);
	else
		ret = setup_layout_fast();

	return ret;
}

/**
 * dune_init_ex - Enables DUNE mode for the currently running process
 * 
 * @map_all: setup the entire address space instead of just the mapped regions
 * 
 * Returns 0 on success, otherwise failure
 */
int dune_init_ex(bool map_all)
{
	int ret = 0, dune_fd, i;
	struct dune_percpu *percpu;
	struct dune_config conf;

	if (arch_prctl(ARCH_GET_FS, &arch_fs) == -1) {
		printf("dune: failed to get FS register\n");
		return -EIO;
	}

	percpu = malloc(sizeof(struct dune_percpu));
	if (!percpu)
		return -ENOMEM;

	percpu->kfs_base = arch_fs;
	percpu->ufs_base = arch_fs;

	dune_fd = open("/dev/dune", O_RDWR);
	if (dune_fd <= 0) {
		printf("dune: failed to open DUNE device\n");
		return -EIO;
	}

	pgroot = memalign(PGSIZE, PGSIZE);
	if (!pgroot)
		return -ENOMEM;
	memset(pgroot, 0, PGSIZE);

	conf.rip = (__u64) &__dune_ret;
	conf.rsp = 0;
	conf.cr3 = (physaddr_t) pgroot;

	if ((ret = dune_page_init())) {
		printf("dune: unable to initialize page manager\n");
		goto err;
	}

	if ((ret = setup_layout(dune_fd, map_all))) {
		printf("dune: unable to setup memory layout\n");
		goto err;
	}

	setup_syscall(dune_fd);

#if 0
	if (mlockall(MCL_CURRENT | MCL_FUTURE) == -1) {
		printf("dune: failed to lock memory\n");
		ret = -EIO;
		goto err;
	}
#endif

	for (i = 1; i < 32; i++) {
		struct sigaction sa;

		if (i == SIGSTOP || i == SIGKILL)
			continue;

		memset(&sa, 0, sizeof(sa));

		sa.sa_handler = SIG_IGN;

		if (sigaction(i, &sa, NULL) == -1)
			err(1, "sigaction() %d", i);
	}

	ret = __dune_enter(dune_fd, &conf);
	if (ret) {
		printf("dune: entry to DUNE mode failed\n");
		ret = -EIO;
		goto err;
	}

	dune_boot(percpu);

	return 0;

err:
	close(dune_fd);
	return ret;
}

int dune_init(void)
{
	return dune_init_ex(1);
}
