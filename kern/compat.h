#ifndef __DUNE_COMPAT_H_
#define __DUNE_COMPAT_H_

#include <linux/version.h>

#if KERNEL_VERSION(3, 1, 0) <= LINUX_VERSION_CODE
#include <asm/fpu/api.h>
#else
#include <asm/i387.h>
#endif

#if KERNEL_VERSION(4, 1, 0) <= LINUX_VERSION_CODE
#include <asm/fpu/internal.h>
#elif KERNEL_VERSION(3, 4, 0) <= LINUX_VERSION_CODE
#include <asm/fpu-internal.h>
#endif

#if !defined(VMX_EPT_AD_BIT)
#define VMX_EPT_AD_BIT		BIT_ULL(21)
#define VMX_EPT_AD_ENABLE_BIT	BIT_ULL(6)
#endif

#ifndef VMX_EPT_EXTENT_INDIVIDUAL_BIT
#define VMX_EPT_EXTENT_INDIVIDUAL_BIT		BIT_ULL(24)
#endif

#ifndef X86_CR4_PCIDE
#define X86_CR4_PCIDE		0x00020000 /* enable PCID support */
#endif

#ifndef SECONDARY_EXEC_ENABLE_INVPCID
#define SECONDARY_EXEC_ENABLE_INVPCID	0x00001000
#endif

#ifndef X86_CR4_FSGSBASE
#define X86_CR4_FSGSBASE	X86_CR4_RDWRGSFS
#endif

#ifndef AR_TYPE_BUSY_64_TSS
#define AR_TYPE_BUSY_64_TSS VMX_AR_TYPE_BUSY_64_TSS
#endif

#if KERNEL_VERSION(4, 3, 0) <= LINUX_VERSION_CODE
static inline struct page *alloc_pages_exact_node(int nid, gfp_t gfp_mask,
						  unsigned int order) {
	return alloc_pages_node(nid, gfp_mask, order);
}
#endif

#if KERNEL_VERSION(4, 1, 0) <= LINUX_VERSION_CODE & defined(_DO_FORK)
typedef long (*do_fork_hack) (unsigned long, unsigned long, unsigned long,
				int __user *, int __user *, unsigned long);
static do_fork_hack __dune_do_fork = (do_fork_hack) _DO_FORK;
static inline long
dune_do_fork(unsigned long clone_flags, unsigned long stack_start,
	     struct pt_regs *regs, unsigned long stack_size,
	     int __user *parent_tidptr, int __user *child_tidptr,
	     unsigned long tls)
{
	struct pt_regs tmp;
	struct pt_regs *me = current_pt_regs();
	long ret;

	memcpy(&tmp, me, sizeof(struct pt_regs));
	memcpy(me, regs, sizeof(struct pt_regs));

	ret = __dune_do_fork(clone_flags, stack_start, stack_size,
			     parent_tidptr, child_tidptr, tls);

	memcpy(me, &tmp, sizeof(struct pt_regs));
	return ret;
}
#elif KERNEL_VERSION(3, 5, 0) <= LINUX_VERSION_CODE & defined(DO_FORK)
typedef long (*do_fork_hack) (unsigned long, unsigned long, unsigned long,
			      int __user *, int __user *);
static do_fork_hack __dune_do_fork = (do_fork_hack)DO_FORK;
static inline long
dune_do_fork(unsigned long clone_flags, unsigned long stack_start,
	     struct pt_regs *regs, unsigned long stack_size,
	     int __user *parent_tidptr, int __user *child_tidptr,
	     unsigned long unused)
{
	struct pt_regs tmp;
	struct pt_regs *me = current_pt_regs();
	long ret;

	memcpy(&tmp, me, sizeof(struct pt_regs));
	memcpy(me, regs, sizeof(struct pt_regs));

	ret = __dune_do_fork(clone_flags, stack_start, stack_size,
			     parent_tidptr, child_tidptr);

	memcpy(me, &tmp, sizeof(struct pt_regs));
	return ret;
}
#elif defined(DO_FORK)
typedef long (*do_fork_hack) (unsigned long, unsigned long,
			      struct pt_regs *, unsigned long,
			      int __user *, int __user *);
static do_fork_hack dune_do_fork = (do_fork_hack)DO_FORK;
#endif

#if KERNEL_VERSION(3, 19, 0) > LINUX_VERSION_CODE
static inline unsigned long __read_cr4(void)
{
	return read_cr4();
}

static inline void cr4_set_bits(unsigned long mask)
{
	write_cr4(read_cr4() | mask);
}

static inline void cr4_clear_bits(unsigned long mask)
{
	write_cr4(read_cr4() & ~mask);
}
#endif

#if KERNEL_VERSION(4, 1, 0) <= LINUX_VERSION_CODE
static inline void compat_fpu_restore(void)
{
	if (!current->thread.fpu.fpregs_active)
		fpu__restore(&current->thread.fpu);
}
#else
static inline void compat_fpu_restore(void)
{
	if (!__thread_has_fpu(current))
		math_state_restore();
}
#endif

#if KERNEL_VERSION(3, 18, 0) > LINUX_VERSION_CODE
#define _PAGE_CACHE_MODE_WB _PAGE_CACHE_WB
#define _PAGE_CACHE_MODE_WC _PAGE_CACHE_WC
static inline long pgprot2cachemode(pgprot_t pgprot)
{
	return pgprot_val(pgprot) & _PAGE_CACHE_MASK;
}
#endif

#endif /* __DUNE_COMPAT_H_ */
