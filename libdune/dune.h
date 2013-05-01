/*
 * dune.h - the libdune API
 */

#include <stdbool.h>
#include <sys/types.h>
#include <sys/queue.h>
#include "mmu.h"
#include "elf.h"
#include "fpu.h"

typedef void (*sighandler_t)(int);

// utilities

static inline unsigned long dune_get_ticks(void)
{
	unsigned int a, d;
	asm volatile("rdtsc" : "=a" (a), "=d" (d));
	return ((unsigned long) a) | (((unsigned long) d) << 32);
}

extern int dune_printf(const char *fmt, ...);
extern void dune_die(void);
extern void * dune_mmap(void *addr, size_t length, int prot,
		       int flags, int fd, off_t offset);
extern sighandler_t dune_signal(int sig, sighandler_t cb);
extern unsigned long dune_get_user_fs(void);
extern void dune_set_user_fs(unsigned long fs_base);

#ifndef assert
#define assert(expr) \
if (!(expr)) { \
	dune_printf("ASSERT(" #expr ") at %s:%d in function %s\n", \
			   __FILE__, __LINE__, __func__); \
	dune_die(); \
}
#endif /* assert */

// fault handling

/*
 * We use the same general GDT layout as Linux so that can we use
 * the same syscall MSR values. In practice only code segments
 * matter, since ia-32e mode ignores most of segment values anyway,
 * but just to be extra careful we match data as well.
 */
#define GD_KT		0x10
#define GD_KD		0x18
#define GD_UD		0x28
#define GD_UT		0x30
#define GD_TSS		0x38
#define GD_TSS2		0x40
#define NR_GDT_ENTRIES	9

struct dune_tf {
	/* manually saved, arguments */
	uint64_t rdi;
	uint64_t rsi;
	uint64_t rdx;
	uint64_t rcx;
	uint64_t r8;
	uint64_t r9;
	uint64_t r10;
	uint64_t r11;

	/* saved by C calling conventions */
	uint64_t rbx;
	uint64_t rbp;
	uint64_t r12;
	uint64_t r13;
	uint64_t r14;
	uint64_t r15;

	/* system call number, ret */
	uint64_t rax;

	/* exception frame */
	uint32_t err;
	uint32_t pad1;
	uint64_t rip;
	uint16_t cs;
	uint16_t pad2[3];
	uint64_t rflags;
	uint64_t rsp;
	uint16_t ss;
	uint16_t pad3[3];
} __attribute__((packed));

#define ARG0(tf)        ((tf)->rdi)
#define ARG1(tf)        ((tf)->rsi)
#define ARG2(tf)        ((tf)->rdx)
#define ARG3(tf)        ((tf)->rcx)
#define ARG4(tf)        ((tf)->r8)
#define ARG5(tf)        ((tf)->r9)

typedef void (*dune_intr_cb) (struct dune_tf *tf);
typedef void (*dune_pgflt_cb) (uintptr_t addr, uint64_t fec,
			      struct dune_tf *tf);
typedef void (*dune_syscall_cb) (struct dune_tf *tf);

// XXX: Must match kern/dune.h
#define DUNE_SIGNAL_INTR_BASE 200

extern int dune_register_intr_handler(int vec, dune_intr_cb cb);
extern int dune_register_signal_handler(int signum, dune_intr_cb cb);
extern void dune_register_pgflt_handler(dune_pgflt_cb cb);
extern void dune_register_syscall_handler(dune_syscall_cb cb);

extern void dune_pop_trap_frame(struct dune_tf *tf);
extern int dune_jump_to_user(struct dune_tf *tf);
extern void dune_ret_from_user(int ret)  __attribute__ ((noreturn));
extern void dune_dump_trap_frame(struct dune_tf *tf);
extern void dune_passthrough_syscall(struct dune_tf *tf);

// page allocation

SLIST_HEAD(page_head, page);
typedef SLIST_ENTRY(page) page_entry_t;

struct page {
	page_entry_t link;
	uint64_t ref;
};

extern struct page *pages;
extern int num_pages;

#define PAGEBASE	0x200000000
#define MAX_PAGES	(1ul << 20) /* 4 GB of memory */

extern struct page * dune_page_alloc(void);
extern void dune_page_free(struct page *pg);
extern void dune_page_stats(void);

static inline struct page * dune_pa2page(physaddr_t pa)
{
	return &pages[PPN(pa - PAGEBASE)];
}

static inline physaddr_t dune_page2pa(struct page *pg)
{
	return PAGEBASE + ((pg - pages) << PGSHIFT);
}

extern bool dune_page_isfrompool(physaddr_t pa);

static inline struct page * dune_page_get(struct page *pg)
{
	assert(pg >= pages);
	assert(pg < (pages + num_pages));

	pg->ref++;

	return pg;
}

static inline void dune_page_put(struct page *pg)
{
	assert(pg >= pages);
	assert(pg < (pages + num_pages));

	pg->ref--;

	if (!pg->ref)
		dune_page_free(pg);
}

// virtual memory

extern ptent_t *pgroot;
extern uintptr_t mmap_base;
extern uintptr_t stack_base;

static inline uintptr_t dune_mmap_addr_to_pa(void *ptr)
{
	return ((uintptr_t) ptr) - mmap_base + 0x400000000;
}

static inline uintptr_t dune_stack_addr_to_pa(void *ptr)
{
	return ((uintptr_t) ptr) - stack_base + 0x800000000;
}

static inline uintptr_t dune_va_to_pa(void *ptr)
{
	if ((uintptr_t) ptr >= stack_base)
		return dune_stack_addr_to_pa(ptr);
	else if ((uintptr_t) ptr >= mmap_base)
		return dune_mmap_addr_to_pa(ptr);
	else
		return (uintptr_t) ptr;
}

#define PERM_NONE  	0	/* no access */
#define PERM_R		0x0001	/* read permission */
#define PERM_W		0x0002	/* write permission */
#define PERM_X		0x0004	/* execute permission */
#define PERM_U		0x0008	/* user-level permission */
#define PERM_COW	0x0010	/* COW flag */
#define PERM_USR1	0x1000  /* User flag 1 */
#define PERM_USR2	0x2000  /* User flag 2 */
#define PERM_USR3	0x3000  /* User flag 3 */
#define PERM_BIG	0x0100	/* Use large pages */

// Helper Macros
#define PERM_SCODE	(PERM_R | PERM_X)
#define PERM_STEXT	(PERM_R | PERM_W)
#define PERM_SSTACK	PERM_STEXT
#define PERM_UCODE	(PERM_R | PERM_U | PERM_X)
#define PERM_UTEXT	(PERM_R | PERM_U | PERM_W)
#define PERM_USTACK	PERM_UTEXT

static inline void dune_flush_tlb_one(unsigned long addr)
{
	asm ("invlpg (%0)" :: "r" (addr) : "memory");
}

static inline void dune_flush_tlb(void)
{
	asm ("mov %%cr3, %%rax\n"
	     "mov %%rax, %%cr3\n" ::: "rax");
}

#define CR3_NOFLUSH	(1UL << 63)

static inline void load_cr3(unsigned long cr3)
{       
        asm("mov %%rax, %%cr3\n" : : "a" (cr3));
}

static inline void __invpcid(int mode, unsigned long addr)
{
	struct {
		unsigned long eptp, gpa;
	} operand = {1, addr};
	asm volatile("invpcid (%%rax), %%rcx" ::
		     "a" (&operand), "c" (mode) : "cc", "memory");
}

/* Define beginning and end of VA space */
#define VA_START		((void *)0)
#define VA_END			((void *)-1)

enum {
	CREATE_NONE = 0,
	CREATE_NORMAL = 1,
	CREATE_BIG = 2,
};

extern int dune_vm_mprotect(ptent_t *root, void *va, size_t len, int perm);
extern int dune_vm_map_phys(ptent_t *root, void *va, size_t len, void *pa, int perm);
extern int dune_vm_map_pages(ptent_t *root, void *va, size_t len, int perm);
extern void dune_vm_unmap(ptent_t *root, void *va, size_t len);
extern int dune_vm_lookup(ptent_t *root, void *va, int create, ptent_t **pte_out);

extern int dune_vm_insert_page(ptent_t *root, void *va, struct page *pg, int perm);
extern struct page * dune_vm_lookup_page(ptent_t *root, void *va);

extern ptent_t * dune_vm_clone(ptent_t *root);
extern void dune_vm_free(ptent_t *root);
extern void dune_vm_default_pgflt_handler(uintptr_t addr, uint64_t fec);

typedef int (*page_walk_cb)(const void *arg, ptent_t *ptep, void *va);
extern int dune_vm_page_walk(ptent_t *root, void *start_va, void *end_va,
			    page_walk_cb cb, const void *arg);

// process memory maps

#define PROCMAP_TYPE_UNKNOWN	0x00
#define PROCMAP_TYPE_FILE	0x01
#define PROCMAP_TYPE_ANONYMOUS	0x02
#define PROCMAP_TYPE_HEAP	0x03
#define PROCMAP_TYPE_STACK	0x04
#define PROCMAP_TYPE_VSYSCALL	0x05
#define PROCMAP_TYPE_VDSO	0x06

struct dune_procmap_entry {
	uintptr_t	begin;
	uintptr_t	end;
	uint64_t	offset;
	bool		r; // Readable
	bool		w; // Writable
	bool		x; // Executable
	bool		p; // Private (or shared)
	char		*path;
	int			type;
};

typedef void (*dune_procmap_cb)(const struct dune_procmap_entry *);

extern void dune_procmap_iterate(dune_procmap_cb cb);
extern void dune_procmap_dump();

// elf helper functions

struct dune_elf {
	int		fd;
	unsigned char	*mem;
	int		len;
	Elf64_Ehdr	hdr;
	Elf64_Phdr	*phdr;
	Elf64_Shdr	*shdr;
	char		*shdrstr;
	void		*priv;
};

typedef int (*dune_elf_phcb)(struct dune_elf *elf, Elf64_Phdr *phdr);
typedef int (*dune_elf_shcb)(struct dune_elf *elf, const char *sname,
		                     int snum, Elf64_Shdr *shdr);

extern int dune_elf_open(struct dune_elf *elf, const char *path);
extern int dune_elf_open_mem(struct dune_elf *elf, void *mem, int len);
extern int dune_elf_close(struct dune_elf *elf);
extern int dune_elf_dump(struct dune_elf *elf);
extern int dune_elf_iter_sh(struct dune_elf *elf, dune_elf_shcb cb);
extern int dune_elf_iter_ph(struct dune_elf *elf, dune_elf_phcb cb);
extern int dune_elf_load_ph(struct dune_elf *elf, Elf64_Phdr *phdr, off_t off);

// entry routines

extern int dune_init(bool map_full);
extern int dune_enter();

/**
 * dune_init_and_enter - initializes libdune and enters "Dune mode"
 * 
 * This is a simple initialization routine that handles everything
 * in one go. Note that you still need to call dune_enter() in
 * each new forked child or thread.
 * 
 * Returns 0 on success, otherwise failure.
 */
static inline int dune_init_and_enter(void)
{
	int ret;
	
	if ((ret = dune_init(1)))
		return ret;
	
	return dune_enter();
}
