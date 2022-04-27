#ifndef __DUNE_COMPAT_H_
#define __DUNE_COMPAT_H_

#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,0,0)
#include <asm/io.h>

#define ASM_VMX_VMCLEAR_RAX     ".byte 0x66, 0x0f, 0xc7, 0x30"
#define ASM_VMX_VMLAUNCH        ".byte 0x0f, 0x01, 0xc2"
#define ASM_VMX_VMRESUME        ".byte 0x0f, 0x01, 0xc3"
#define ASM_VMX_VMPTRLD_RAX     ".byte 0x0f, 0xc7, 0x30"
#define ASM_VMX_VMREAD_RDX_RAX  ".byte 0x0f, 0x78, 0xd0"
#define ASM_VMX_VMWRITE_RAX_RDX ".byte 0x0f, 0x79, 0xd0"
#define ASM_VMX_VMWRITE_RSP_RDX ".byte 0x0f, 0x79, 0xd4"
#define ASM_VMX_VMXOFF          ".byte 0x0f, 0x01, 0xc4"
#define ASM_VMX_VMXON_RAX       ".byte 0xf3, 0x0f, 0xc7, 0x30"
#define ASM_VMX_INVEPT          ".byte 0x66, 0x0f, 0x38, 0x80, 0x08"
#define ASM_VMX_INVVPID         ".byte 0x66, 0x0f, 0x38, 0x81, 0x08"

#define VMX_EPT_DEFAULT_MT     VMX_EPTP_MT_WB
#define VMX_EPT_DEFAULT_GAW    3
#define VMX_EPT_GAW_EPTP_SHIFT 3

#define SECONDARY_EXEC_RDTSCP          SECONDARY_EXEC_ENABLE_RDTSCP
#define VMX_EPT_AD_ENABLE_BIT          VMX_EPTP_AD_ENABLE_BIT
#define VMX_EPT_EXTENT_INDIVIDUAL_ADDR 0

#define read_cr3                       __read_cr3

#define CPU_BASED_USE_TSC_OFFSETING               CPU_BASED_USE_TSC_OFFSETTING
#define FEATURE_CONTROL_LOCKED                    FEAT_CTL_LOCKED
#define FEATURE_CONTROL_VMXON_ENABLED_OUTSIDE_SMX FEAT_CTL_VMX_ENABLED_OUTSIDE_SMX
#define FEATURE_CONTROL_VMXON_ENABLED_INSIDE_SMX  FEAT_CTL_VMX_ENABLED_INSIDE_SMX
#define MSR_IA32_FEATURE_CONTROL                  MSR_IA32_FEAT_CTL

static inline void native_store_idt(struct desc_ptr *dtr)
{
    asm volatile("sidt %0" : "=m"(*dtr));
}

#define __addr_ok(addr) ((unsigned long __force)(addr) < user_addr_max())
#define mmap_sem mmap_lock

typedef struct ldttss_desc ldttss_desc_t;
#else
typedef struct ldttss_desc64 ldttss_desc_t;
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,1,0)
#include <asm/fpu/api.h>
#else
#include <asm/i387.h>
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,1,0)
#include <asm/fpu/internal.h>
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,4,0)
#include <asm/fpu-internal.h>
#endif

#if !defined(VMX_EPT_AD_BIT)
#define VMX_EPT_AD_BIT          (1ull << 21)
#define VMX_EPT_AD_ENABLE_BIT   (1ull << 6)
#endif

#ifndef VMX_EPT_EXTENT_INDIVIDUAL_BIT
#define VMX_EPT_EXTENT_INDIVIDUAL_BIT           (1ull << 24)
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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,3,0)
static inline struct page *alloc_pages_exact_node(int nid, gfp_t gfp_mask,
                                                    unsigned int order){
	return alloc_pages_node(nid, gfp_mask, order);
}
#endif


#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,0,0) & defined(KERNEL_CLONE)
typedef long (*kernel_clone_fn)(struct kernel_clone_args *);
static kernel_clone_fn __kernel_clone = (kernel_clone_fn)KERNEL_CLONE;
static inline long dune_do_fork(unsigned long clone_flags,
                                unsigned long stack_start, struct pt_regs *regs,
                                unsigned long stack_size,
                                int __user *parent_tidptr,
                                int __user *child_tidptr, unsigned long tls)
{
    struct pt_regs tmp;
    struct kernel_clone_args args;
    struct pt_regs *me = current_pt_regs();
    long ret;

    memcpy(&tmp, me, sizeof(struct pt_regs));
    memcpy(me, regs, sizeof(struct pt_regs));

    args = (struct kernel_clone_args){
        .flags = (lower_32_bits(clone_flags) & ~CSIGNAL),
        .child_tid = child_tidptr,
        .parent_tid = parent_tidptr,
        .stack = stack_start,
        .stack_size = stack_size,
        .tls = tls,
        .exit_signal = (lower_32_bits(clone_flags) & CSIGNAL),
    };

    ret = __kernel_clone(&args);

    memcpy(me, &tmp, sizeof(struct pt_regs));
    return ret;
}
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4,1,0) & defined(_DO_FORK)
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
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,5,0) & defined(DO_FORK)
typedef long (*do_fork_hack) (unsigned long, unsigned long, unsigned long,
                              int __user *, int __user *);
static do_fork_hack __dune_do_fork = (do_fork_hack) DO_FORK;
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
static do_fork_hack dune_do_fork = (do_fork_hack) DO_FORK;
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,19,0)
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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,0,0)
static inline void compat_fpu_restore(void)
{
    // TODO: fpu_restore
    // if (!current->thread.fpu.fpregs_active)
    //     fpu__restore(&current->thread.fpu);
}
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4,1,0)
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

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,18,0)
#define _PAGE_CACHE_MODE_WB _PAGE_CACHE_WB
#define _PAGE_CACHE_MODE_WC _PAGE_CACHE_WC
static inline long pgprot2cachemode(pgprot_t pgprot)
{
	return pgprot_val(pgprot) & _PAGE_CACHE_MASK;
}
#endif

#endif /* __DUNE_COMPAT_H_ */
