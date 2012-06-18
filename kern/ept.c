/**
 * ept.c - Support for Intel's Extended Page Tables
 *
 * Authors:
 *   Adam Belay <abelay@stanford.edu>
 *
 * Right now we support EPT by making a sort of 'shadow' copy of the Linux
 * process page table. In the future, a more invasive architecture port
 * to VMX x86 could provide better performance by eliminating the need for
 * two copies of each page table entry, relying instead on only the EPT
 * format.
 * 
 * This code is only a prototype and could benefit from a more comprehensive
 * review in terms of performance and correctness. Also, the implications
 * of threaded processes haven't been fully considered.
 *
 * Some of the low-level EPT functions are based on KVM.
 * Original Authors:
 *   Avi Kivity   <avi@qumranet.com>
 *   Yaniv Kamay  <yaniv@qumranet.com>
 */

#include <linux/mm.h>
#include <linux/hugetlb.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <asm/pgtable.h>

#include "dune.h"
#include "vmx.h"

#define EPT_LEVELS	4	/* 0 through 3 */
#define HUGE_PAGE_SIZE	2097152

typedef unsigned long gpa_t;

static inline bool cpu_has_vmx_ept_execute_only(void)
{
	return vmx_capability.ept & VMX_EPT_EXECUTE_ONLY_BIT;
}

static inline bool cpu_has_vmx_eptp_uncacheable(void)
{
	return vmx_capability.ept & VMX_EPTP_UC_BIT;
}

static inline bool cpu_has_vmx_eptp_writeback(void)
{
	return vmx_capability.ept & VMX_EPTP_WB_BIT;
}

static inline bool cpu_has_vmx_ept_2m_page(void)
{
	return vmx_capability.ept & VMX_EPT_2MB_PAGE_BIT;
}

static inline bool cpu_has_vmx_ept_1g_page(void)
{
	return vmx_capability.ept & VMX_EPT_1GB_PAGE_BIT;
}

static inline bool cpu_has_vmx_ept_4levels(void)
{
	return vmx_capability.ept & VMX_EPT_PAGE_WALK_4_BIT;
}

static inline bool cpu_has_vmx_invept_individual_addr(void)
{
	return vmx_capability.ept & VMX_EPT_EXTENT_INDIVIDUAL_BIT;
}

static inline bool cpu_has_vmx_invept_context(void)
{
	return vmx_capability.ept & VMX_EPT_EXTENT_CONTEXT_BIT;
}

static inline bool cpu_has_vmx_invept_global(void)
{
	return vmx_capability.ept & VMX_EPT_EXTENT_GLOBAL_BIT;
}

static inline void __invept(int ext, u64 eptp, gpa_t gpa)
{
	struct {
		u64 eptp, gpa;
	} operand = {eptp, gpa};

	asm volatile (ASM_VMX_INVEPT
			/* CF==1 or ZF==1 --> rc = -1 */
			"; ja 1f ; ud2 ; 1:\n"
			: : "a" (&operand), "c" (ext) : "cc", "memory");
}

static inline void ept_sync_global(void)
{
	if (cpu_has_vmx_invept_global())
		__invept(VMX_EPT_EXTENT_GLOBAL, 0, 0);
}

static inline void ept_sync_context(u64 eptp)
{
	if (cpu_has_vmx_invept_context())
		__invept(VMX_EPT_EXTENT_CONTEXT, eptp, 0);
	else
		ept_sync_global();
}

static inline void ept_sync_individual_addr(u64 eptp, gpa_t gpa)
{
	if (cpu_has_vmx_invept_individual_addr())
		__invept(VMX_EPT_EXTENT_INDIVIDUAL_ADDR,
				eptp, gpa);
	else
		ept_sync_context(eptp);
}

void ept_sync_vcpu(struct vmx_vcpu *vcpu)
{
	ept_sync_context(vcpu->eptp);
}

#define VMX_EPT_FAULT_READ	0x01
#define VMX_EPT_FAULT_WRITE	0x02
#define VMX_EPT_FAULT_INS	0x04

typedef unsigned long epte_t;

#define __EPTE_READ	0x01
#define __EPTE_WRITE	0x02
#define __EPTE_EXEC	0x04
#define __EPTE_IPAT	0x40
#define __EPTE_SZ	0x80
#define __EPTE_TYPE(n)	(((n) & 0x7) << 3)

enum {
	EPTE_TYPE_UC = 0, /* uncachable */
	EPTE_TYPE_WC = 1, /* write combining */
	EPTE_TYPE_WT = 4, /* write through */
	EPTE_TYPE_WP = 5, /* write protected */
	EPTE_TYPE_WB = 6, /* write back */
};

#define __EPTE_NONE	0
#define __EPTE_FULL	(__EPTE_READ | __EPTE_WRITE | __EPTE_EXEC)

#define EPTE_ADDR	(~(PAGE_SIZE - 1))
#define EPTE_FLAGS	(PAGE_SIZE - 1)

static inline uintptr_t epte_addr(epte_t epte)
{
	return (epte & EPTE_ADDR);
}

static inline uintptr_t epte_page_vaddr(epte_t epte)
{
	return (uintptr_t) __va(epte_addr(epte));
}

static inline epte_t epte_flags(epte_t epte)
{
	return (epte & EPTE_FLAGS);
}

static inline int epte_present(epte_t epte)
{
	return (epte & __EPTE_FULL) > 0;
}

static inline int epte_big(epte_t epte)
{
	return (epte & __EPTE_SZ) > 0;
}

static epte_t convert_to_epte(pgprotval_t prot, uintptr_t addr, int leaf)
{
	epte_t val = 0;

	val |= (epte_t) addr;

	if (prot & _PAGE_PRESENT) {
		val |= __EPTE_READ;

		if (prot & _PAGE_RW)
			val |= __EPTE_WRITE;
		if (!(prot & _PAGE_NX))
			val |= __EPTE_EXEC;
		if (prot & _PAGE_PSE)
			val |= __EPTE_SZ;
	}

	if (leaf) {
		val |= __EPTE_TYPE(EPTE_TYPE_WB);
		val |= __EPTE_IPAT;
	}

	return val;
}

static unsigned long hva_to_gpa(struct vmx_vcpu *vcpu, unsigned long addr)
{
	uintptr_t mmap_start;

	if (!current->mm) {
		printk(KERN_ERR "ept: proc has no MM %d\n", current->pid);
		return GPA_ADDR_INVAL;
	}

	BUG_ON(!current->mm);

	mmap_start = LG_ALIGN(current->mm->mmap_base) - GPA_SIZE;

	if ((addr & ~GPA_MASK) == 0)
		return (addr & GPA_MASK) | GPA_ADDR_PROC;
	else if (addr < LG_ALIGN(current->mm->mmap_base) && addr >= mmap_start)
		return (addr - mmap_start) | GPA_ADDR_MAP;
	else if ((addr & ~GPA_MASK) == (current->mm->start_stack & ~GPA_MASK))
		return (addr & GPA_MASK) | GPA_ADDR_STACK;
	else
		return GPA_ADDR_INVAL;
}

static unsigned long gpa_to_hva(struct vmx_vcpu *vcpu, unsigned long addr)
{
	if ((addr & ~GPA_MASK) == GPA_ADDR_PROC)
		return (addr & GPA_MASK);
	else if ((addr & ~GPA_MASK) == GPA_ADDR_MAP)
		return (addr & GPA_MASK) + LG_ALIGN(current->mm->mmap_base) - GPA_SIZE;
	else if ((addr & ~GPA_MASK) == GPA_ADDR_STACK)
		return (addr & GPA_MASK) | (current->mm->start_stack & ~GPA_MASK);
	else
		return GPA_ADDR_INVAL;
}

#define ADDR_TO_IDX(la, n) \
	((((unsigned long) (la)) >> (12 + 9 * (n))) & ((1 << 9) - 1))

static int
ept_lookup_gpa(struct vmx_vcpu *vcpu, void *gpa, int level,
	   int create, epte_t **epte_out)
{
	int i;
	epte_t *dir = (epte_t *) __va(vcpu->ept_root);

	for (i = EPT_LEVELS - 1; i > level; i--) {
		int idx = ADDR_TO_IDX(gpa, i);

		if (!epte_present(dir[idx])) {
			void *page;

			if (!create)
				return -ENOENT;

			page = (void *) __get_free_page(GFP_KERNEL);
			if (!page)
				return -ENOMEM;

			memset(page, 0, PAGE_SIZE);
			dir[idx] = epte_addr(virt_to_phys(page)) |
				   __EPTE_FULL;
		}

		if (epte_big(dir[idx])) {
			if (i != 1)
				return -EINVAL;
			level = i;
			break;
		}

		dir = (epte_t *) epte_page_vaddr(dir[idx]);
	}

	*epte_out = &dir[ADDR_TO_IDX(gpa, level)];
	return 0;
}

static int
ept_lookup(struct vmx_vcpu *vcpu, void *hva, int level,
	   int create, epte_t **epte_out)
{
	void *gpa = (void *) hva_to_gpa(vcpu, (unsigned long) hva);

	if (gpa == (void *) GPA_ADDR_INVAL) {
		printk(KERN_ERR "ept: hva %p is out of range\n", hva);
		printk(KERN_ERR "ept: mem_base %lx, stack_start %lx\n",
		       current->mm->mmap_base, current->mm->start_stack);
		return -EINVAL;
	}

	return ept_lookup_gpa(vcpu, gpa, level, create, epte_out);
}

static int
__vmx_clone_entry(struct vmx_vcpu *vcpu, pgprotval_t prot, unsigned long va)
{
	int ret;
	epte_t *epte;

	struct page *page[1];
	int make_write = (prot & _PAGE_RW) ? 1 : 0;

	ret = get_user_pages(current, current->mm, va, 1,
			     make_write, 0, page, NULL);
	if (ret != 1) {
		printk(KERN_INFO "vmx: failed to get page at va %lx\n", va);
		return -EFAULT;
	}

	ret = ept_lookup(vcpu, (void *) va,
			 (prot & _PAGE_PSE) ? 1 : 0, 1, &epte);
	if (ret) {
		printk(KERN_ERR "ept: failed to lookup EPT entry\n");
		return -EIO;
	}

	*epte = convert_to_epte(prot, (page_to_phys(page[0]) & PTE_PFN_MASK),
				1);

	return 0;
}

#define IDX_TO_ADDR(i, j, k, l) \
	((((u64) (i)) << 39) | \
	 (((u64) (j)) << 30) | \
	 (((u64) (k)) << 21) | \
	 (((u64) (l)) << 12))

static int vmx_create_clone(struct vmx_vcpu *vcpu)
{
	int i, j, k, l, ret;
	pgd_t *pgd = (pgd_t *) current->mm->pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	for (i = 0; i < PTRS_PER_PGD / 2; i++) {
		pgprotval_t prot = pgd_val(pgd[i]);
		if (!(prot & _PAGE_PRESENT) ||
		    !(prot & _PAGE_USER))
			continue;

		pud = (pud_t *) pgd_page_vaddr(pgd[i]);

		for (j = 0; j < PTRS_PER_PUD; j++) {
			pgprotval_t prot = pud_val(pud[j]);
			if (!(prot & _PAGE_PRESENT) ||
			    !(prot & _PAGE_USER))
				continue;
			if (prot & _PAGE_PSE)
				return -EINVAL;

			pmd = (pmd_t *) pud_page_vaddr(pud[j]);

			for (k = 0; k < PTRS_PER_PMD; k++) {
				pgprotval_t prot = pmd_val(pmd[k]);
				if (!(prot & _PAGE_PRESENT) ||
				    !(prot & _PAGE_USER))
					continue;
				if (prot & _PAGE_PSE) {
					ret = __vmx_clone_entry(vcpu, prot,
						IDX_TO_ADDR(i, j, k, 0));
					if (ret)
						return ret;
					continue;
				}

				pte = (pte_t *) pmd_page_vaddr(pmd[k]);

				for (l = 0; l < PTRS_PER_PTE; l++) {
					pgprotval_t prot = pte_val(pte[l]);
					if (!(prot & _PAGE_PRESENT) ||
					    !(prot & _PAGE_USER))
						continue;

					ret = __vmx_clone_entry(vcpu, prot,
						IDX_TO_ADDR(i, j, k, l));
					if (ret)
						return ret;
				}
			}
		}
	}

	return 0;
}

static void free_ept_page(epte_t epte)
{
	struct page *page = pfn_to_page((epte & PTE_PFN_MASK) >> PAGE_SHIFT);

	if (epte & __EPTE_WRITE)
		set_page_dirty(page);
	put_page(page);
}

static void vmx_free_ept(unsigned long ept_root)
{
	epte_t *pgd = (epte_t *) __va(ept_root);
	int i, j, k, l;

	for (i = 0; i < PTRS_PER_PGD; i++) {
		epte_t *pud = (epte_t *) epte_page_vaddr(pgd[i]);
		if (!epte_present(pgd[i]))
			continue;

		for (j = 0; j < PTRS_PER_PUD; j++) {
			epte_t *pmd = (epte_t *) epte_page_vaddr(pud[j]);
			if (!epte_present(pud[j]))
				continue;
			if (epte_flags(pud[j]) & __EPTE_SZ)
				continue;

			for (k = 0; k < PTRS_PER_PMD; k++) {
				epte_t *pte = (epte_t *) epte_page_vaddr(pmd[k]);
				if (!epte_present(pmd[k]))
					continue;
				if (epte_flags(pmd[k]) & __EPTE_SZ) {
					free_ept_page(pmd[k]);
					continue;
				}

				for (l = 0; l < PTRS_PER_PTE; l++) {
					if (!epte_present(pte[l]))
						continue;

					free_ept_page(pte[l]);
				}

				free_page((unsigned long) pte);
			}

			free_page((unsigned long) pmd);
		}

		free_page((unsigned long) pud);
	}

	free_page((unsigned long) pgd);
}

static int ept_clear_epte(epte_t *epte)
{
	if (*epte == __EPTE_NONE)
		return 0;

	free_ept_page(*epte);
	*epte = __EPTE_NONE;

	return 1;
}

static int ept_set_epte(struct vmx_vcpu *vcpu, int make_write,
			unsigned long gpa, unsigned long hva)
{
	int ret;
	epte_t *epte, flags;
	struct page *page[1];

	ret = get_user_pages_fast(hva, 1, make_write, page);
	if (ret != 1) {
		return ret;
	}

	ret = ept_lookup_gpa(vcpu, (void *) gpa,
			     PageHuge(page[0]) ? 1 : 0, 1, &epte);
	if (ret) {
		printk(KERN_ERR "ept: failed to lookup EPT entry\n");
		return ret;
	}

	if (epte_present(*epte) && (epte_big(*epte) || !PageHuge(page[0])))
		ept_clear_epte(epte);

	flags = __EPTE_READ | __EPTE_EXEC |
		__EPTE_TYPE(EPTE_TYPE_WB) | __EPTE_IPAT;
	if (make_write)
		flags |= __EPTE_WRITE;

	if (PageHuge(page[0])) {
		flags |= __EPTE_SZ;
		if (epte_present(*epte) && !epte_big(*epte))
			free_page(epte_page_vaddr(*epte));
			/* FIXME: free L0 entries too */
		*epte = epte_addr(page_to_phys(page[0]) & ~((1 << 21) - 1)) |
			flags;
	} else
		*epte = epte_addr(page_to_phys(page[0])) | flags;

	return 0;
}

int vmx_do_ept_fault(struct vmx_vcpu *vcpu, unsigned long gpa,
		     unsigned long gva, int fault_flags)
{
	int ret;
	unsigned long hva = gpa_to_hva(vcpu, gpa);
	int make_write = (fault_flags & VMX_EPT_FAULT_WRITE) ? 1 : 0;

	pr_debug("ept: GPA: 0x%lx, GVA: 0x%lx, HVA: 0x%lx, flags: %x\n",
		 gpa, gva, hva, fault_flags);

	ret = ept_set_epte(vcpu, make_write, gpa, hva);

	if (!ret)
		ept_sync_individual_addr(vcpu->eptp, (gpa_t) gpa);

	return ret;
}

/* returns 1 if page table changed, 0 otherwise */
static int ept_invalidate_page(struct vmx_vcpu *vcpu, unsigned long addr)
{
	int ret;
	epte_t *epte;
	void *gpa = (void *) hva_to_gpa(vcpu, (unsigned long) addr);

	if (gpa == (void *) GPA_ADDR_INVAL) {
		printk(KERN_ERR "ept: hva %lx is out of range\n", addr);
		return 0;
	}

	ret = ept_lookup_gpa(vcpu, (void *) gpa, 0, 0, &epte);
	if (ret)
		return 0;

	ret = ept_clear_epte(epte);
	if (ret)
		ept_sync_individual_addr(vcpu->eptp, (gpa_t) gpa);

	return ret;
}

static inline struct vmx_vcpu *mmu_notifier_to_vmx(struct mmu_notifier *mn)
{
	return container_of(mn, struct vmx_vcpu, mmu_notifier);
}

static void ept_mmu_notifier_invalidate_page(struct mmu_notifier *mn,
					     struct mm_struct *mm,
					     unsigned long address)
{
	struct vmx_vcpu *vcpu = mmu_notifier_to_vmx(mn);

	pr_debug("ept: invalidate_page addr %lx\n", address);

	ept_invalidate_page(vcpu, address);
}

static void ept_mmu_notifier_invalidate_range_start(struct mmu_notifier *mn,
						    struct mm_struct *mm,
						    unsigned long start,
						    unsigned long end)
{
	struct vmx_vcpu *vcpu = mmu_notifier_to_vmx(mn);
	int ret;
	epte_t *epte;
	unsigned long pos = start;

	pr_debug("ept: invalidate_range_start start %lx end %lx\n", start, end);

	while (pos < end) {
		ret = ept_lookup(vcpu, (void *) pos, 0, 0, &epte);
		if (!ret) {
			pos += epte_big(*epte) ? HUGE_PAGE_SIZE : PAGE_SIZE;
			ept_clear_epte(epte);
		} else
			pos += PAGE_SIZE;
	}

	ept_sync_context(vcpu->eptp);
}

static void ept_mmu_notifier_invalidate_range_end(struct mmu_notifier *mn,
						  struct mm_struct *mm,
						  unsigned long start,
						  unsigned long end)
{
}

static void ept_mmu_notifier_change_pte(struct mmu_notifier *mn,
					struct mm_struct *mm,
					unsigned long address,
					pte_t pte)
{
	int ret;
	struct vmx_vcpu *vcpu = mmu_notifier_to_vmx(mn);
	unsigned long gpa = hva_to_gpa(vcpu, (unsigned long) address);
	int make_write = (pte_flags(pte) & _PAGE_RW) ? 1 : 0;

//	printk(KERN_INFO "ept: change_pte addr %lx\n", address);

	if (gpa == GPA_ADDR_INVAL) {
		printk(KERN_ERR "ept: hva %lx is out of range\n", address);
		return;
	}

	ret = ept_set_epte(vcpu, make_write, gpa, address);
	if (!ret)
		ept_sync_individual_addr(vcpu->eptp, (gpa_t) gpa);
	else
		printk(KERN_ERR "ept: ept_set_epte failed\n");
}

static int ept_mmu_notifier_clear_flush_young(struct mmu_notifier *mn,
					      struct mm_struct *mm,
					      unsigned long address)
{
	struct vmx_vcpu *vcpu = mmu_notifier_to_vmx(mn);

	printk(KERN_INFO "ept: clear_flush_young addr %lx\n", address);

	return ept_invalidate_page(vcpu, address);
}

static int ept_mmu_notifier_test_young(struct mmu_notifier *mn,
				       struct mm_struct *mm,
				       unsigned long address)
{
	printk(KERN_INFO "ept: test_young addr %lx\n", address);
	return 0;
}

static void ept_mmu_notifier_release(struct mmu_notifier *mn,
				     struct mm_struct *mm)
{
}

static const struct mmu_notifier_ops ept_mmu_notifier_ops = {
	.invalidate_page	= ept_mmu_notifier_invalidate_page,
	.invalidate_range_start	= ept_mmu_notifier_invalidate_range_start,
	.invalidate_range_end	= ept_mmu_notifier_invalidate_range_end,
	.clear_flush_young	= ept_mmu_notifier_clear_flush_young,
	.test_young		= ept_mmu_notifier_test_young,
	.change_pte		= ept_mmu_notifier_change_pte,
	.release		= ept_mmu_notifier_release,
};

int vmx_create_ept(struct vmx_vcpu *vcpu)
{
	void *page = (void *) __get_free_page(GFP_KERNEL);
	int ret;

	if (!page)
		return -ENOMEM;
	memset(page, 0, PAGE_SIZE);

	vcpu->ept_root =  __pa(page);

	down_read(&current->mm->mmap_sem);
	ret = vmx_create_clone(vcpu);
	if (ret) {
		up_read(&current->mm->mmap_sem);
		goto fail;
	}
	up_read(&current->mm->mmap_sem);


	vcpu->mmu_notifier.ops = &ept_mmu_notifier_ops;
	ret = mmu_notifier_register(&vcpu->mmu_notifier, current->mm);
	if (ret)
		goto fail;

	return 0;

fail:
	vmx_free_ept(vcpu->ept_root);

	return ret;
}

void vmx_destroy_ept(struct vmx_vcpu *vcpu)
{
	mmu_notifier_unregister(&vcpu->mmu_notifier, current->mm);
	vmx_free_ept(vcpu->ept_root);
}
