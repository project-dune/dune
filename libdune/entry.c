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
#include <unistd.h>
#include <sys/syscall.h>

#include "../kern/dune.h"
#include "dune.h"
#include "mmu.h"
#include "cpu-x86.h"
#include "local.h"

ptent_t *pgroot;
uintptr_t mmap_base;
uintptr_t stack_base;

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

static __thread struct dune_percpu *lpercpu;

struct dynsym {
	char		*ds_name;
	int		ds_idx;
	int		ds_off;
	struct dynsym	*ds_next;
};

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

/**
 * dune_boot - Brings the user-level OS online
 * @percpu: the thread-local data
 */
static int dune_boot(struct dune_percpu *percpu)
{
	struct tptr _idtr, _gdtr;

	setup_gdt(percpu);

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
		"pushq $1f\n"
		"lretq\n"
		"1:\n"
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

		switch (i) {
		case T_BRKPT:
			id->type |= IDTD_CPL3;
			/* fallthrough */
		case T_DBLFLT:
		case T_NMI:
		case T_MCHK:
			id->ist = 1;
			break;
		}

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

static void *xmalloc(size_t sz)
{
	void *x = malloc(sz);

	if (!x)
		err(1, "malloc()");

	memset(x, 0, sz);

	return x;
}

static int vdso_sh_cb(struct dune_elf *elf, const char *sname,
                      int snum, Elf64_Shdr *shdr)
{
	assert(elf->mem);

	if (shdr->sh_type == SHT_STRTAB && strcmp(sname, ".dynstr") == 0) {
		char *p = (char*) (elf->mem + shdr->sh_offset);
		struct dynsym *ds = elf->priv;

		while ((ds = ds->ds_next))
			ds->ds_name = p + ds->ds_idx;
	} else if (shdr->sh_type == SHT_DYNSYM) {
		Elf64_Sym *s;
		int len;

		len = shdr->sh_size;
		s   = (Elf64_Sym*) (elf->mem + shdr->sh_offset);

		while (len >= sizeof(*s)) {
			if (s->st_value) {
				struct dynsym *head = elf->priv;
				struct dynsym *ds = xmalloc(sizeof(*ds));

				ds->ds_idx = s->st_name;
				ds->ds_off = s->st_value & 0xFFF;

				ds->ds_next = head->ds_next;
				head->ds_next = ds;
			}
			s++;
			len -= sizeof(*s);
		}
	}

	return 0;
}

static void do_vdso(void *addr, char *name)
{
	int sysno = -1;
	void *p;
	int len;
	uint32_t *i;

	extern void _vdso_start(void);
	extern void _vdso_end(void);

//	printf("VDSO %p %s\n", addr, name);

	if (strcmp(name, "__vdso_time") == 0
	    || strcmp(name, "time") == 0) {
		sysno = SYS_time;
	} else if (strcmp(name, "__vdso_clock_gettime") == 0
		   || strcmp(name, "clock_gettime") == 0) {
		sysno = SYS_clock_gettime;
	} else if (strcmp(name, "getcpu") == 0
		|| strcmp(name, "__vdso_getcpu") == 0) {
		sysno = SYS_getcpu;
	} else if (strcmp(name, "gettimeofday") == 0
		   || strcmp(name, "__vdso_gettimeofday") == 0) {
		sysno = SYS_gettimeofday;
	} else {
		printf("Unknown VDSO syscall %s\n", name);
		return;
	}

	asm("jmp _vdso_end\n"
	    "_vdso_start:\n"
	    "mov $0xAAAA, %rax\n"
	    "syscall\n"
	    "ret\n"
	    "_vdso_end:\n");

	p = (unsigned char*) _vdso_start;
	len = (unsigned long) _vdso_end - (unsigned long) _vdso_start;

	memcpy(addr, p, len);

	i = (uint32_t*) (addr + 3);
	if (*i != 0xaaaa)
		err(1, "bad instruction");

	*i = sysno;
}

static void setup_vdso(void *addr)
{
	struct dune_elf elf;
	struct dynsym *ds, *d;
	unsigned char *vdso;
	ptent_t *pte;

	memset(&elf, 0, sizeof(elf));

	ds = xmalloc(sizeof(*ds));
	elf.priv = ds;

	if (dune_elf_open_mem(&elf, addr, PGSIZE))
		err(1, "dune_elf_open_mem()");

	if (elf.hdr.e_type != ET_DYN)
		err(1, "bad elf");

	dune_elf_iter_sh(&elf, vdso_sh_cb);

	vdso = mmap(NULL, PGSIZE, PROT_READ | PROT_WRITE | PROT_EXEC,
		    MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (vdso == MAP_FAILED)
		err(1, "mmap()");

	memcpy(vdso, addr, PGSIZE);

	dune_vm_lookup(pgroot, addr, 1, &pte);
	*pte = PTE_ADDR(dune_va_to_pa(vdso)) | PTE_P | PTE_U;

	while ((d = ds->ds_next)) {
		if (d->ds_name[0])
			do_vdso(vdso + d->ds_off, d->ds_name);

		ds = d;
		free(d);
	}

	free(elf.priv);

	mprotect(vdso, PGSIZE, PROT_READ | PROT_EXEC);
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

	if (ent->type == PROCMAP_TYPE_VDSO) {
		setup_vdso((void*) ent->begin);
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

static void setup_vdso_cb(const struct dune_procmap_entry *ent)
{
	if (ent->type == PROCMAP_TYPE_VDSO) {
		setup_vdso((void*) ent->begin);
		return;
	}
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

	dune_procmap_iterate(setup_vdso_cb);
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

static struct dune_percpu *create_percpu(void)
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

	return percpu;
}

static void free_percpu(struct dune_percpu *percpu)
{
	/* XXX free stack */
	munmap(percpu, PGSIZE);
}

static void map_stack_cb(const struct dune_procmap_entry *e)
{
	unsigned long esp;

	asm ("mov %%rsp, %0" : "=r" (esp));

	if (esp >= e->begin && esp < e->end)
		map_ptr((void*) e->begin, e->end - e->begin);
}

static void map_stack(void)
{
	dune_procmap_iterate(map_stack_cb);
}

static int do_dune_enter(struct dune_percpu *percpu)
{
	struct dune_config conf;
	int ret;

	map_stack();

	conf.rip = (__u64) &__dune_ret;
	conf.rsp = 0;
	conf.cr3 = (physaddr_t) pgroot;

	ret = __dune_enter(dune_fd, &conf);
	if (ret) {
		printf("dune: entry to Dune mode failed, ret is %d\n", ret);
		return -EIO;
	}

	ret = dune_boot(percpu);
	if (ret) {
		printf("dune: problem while booting, unrecoverable\n");
		dune_die();
	}

	return 0;
}

/**
 * dune_enter - transitions a process to "Dune mode"
 *
 * Can only be called after dune_init().
 * 
 * Use this function in each forked child and/or each new thread
 * if you want to re-enter "Dune mode".
 * 
 * Returns 0 on success, otherwise failure.
 */
int dune_enter(void)
{
	struct dune_percpu *percpu;
	int ret;

	// check if this process already entered Dune before a fork...
	if (lpercpu)
		return do_dune_enter(lpercpu);

	percpu = create_percpu();
	if (!percpu)
		return -ENOMEM;

	ret = do_dune_enter(percpu);

	if (ret) {
		free_percpu(percpu);
		return ret;
	}

	lpercpu = percpu;
	return 0;
}

/**
 * dune_init - initializes libdune
 * 
 * @map_full: determines if the full process address space should be mapped
 * 
 * Call this function once before using libdune.
 *
 * Dune supports two memory modes. If map_full is true, then every possible
 * address in the process address space is mapped. Otherwise, only addresses
 * that are used (e.g. set up through mmap) are mapped. Full mapping consumes
 * a lot of memory when enabled, but disabling it incurs slight overhead
 * since pages will occasionally need to be faulted in.
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

	return 0;

err:
	// FIXME: need to free memory
fail_pgroot:
	close(dune_fd);
fail_open:
	return ret;
}

