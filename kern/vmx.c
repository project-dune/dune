/**
 *  vmx.c - The Intel VT-x driver for Dune
 *
 * This file is derived from Linux KVM VT-x support.
 * Copyright (C) 2006 Qumranet, Inc.
 * Copyright 2010 Red Hat, Inc. and/or its affiliates.
 *
 * Original Authors:
 *   Avi Kivity   <avi@qumranet.com>
 *   Yaniv Kamay  <yaniv@qumranet.com>
 *
 * This modified version is simpler because it avoids the following
 * features that are not requirements for Dune:
 *  * Real-mode emulation
 *  * Nested VT-x support
 *  * I/O hardware emulation
 *  * Any of the more esoteric X86 features and registers
 *  * KVM-specific functionality
 *
 * In essence we provide only the minimum functionality needed to run
 * a process in vmx non-root mode rather than the full hardware emulation
 * needed to support an entire OS.
 *
 * This driver is a research prototype and as such has the following
 * limitations:
 *
 * FIXME: Backward compatability is currently a non-goal, and only recent
 * full-featured (EPT, PCID, VPID, etc.) Intel hardware is supported by this
 * driver.
 *
 * FIXME: Eventually we should handle concurrent user's of VT-x more
 * gracefully instead of requiring exclusive access. This would allow
 * Dune to interoperate with KVM and other HV solutions.
 *
 * FIXME: We need to support hotplugged physical CPUs.
 *
 * Authors:
 *   Adam Belay   <abelay@stanford.edu>
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/sched.h>
#include <linux/moduleparam.h>
#include <linux/ftrace_event.h>
#include <linux/slab.h>
#include <linux/tboot.h>
#include <linux/init.h>
#include <linux/smp.h>
#include <linux/percpu.h>
#include <linux/syscalls.h>
#include <linux/version.h>

#include <asm/desc.h>
#include <asm/vmx.h>
#include <asm/unistd_64.h>
#include <asm/virtext.h>
#include <asm/i387.h>

#include "dune.h"
#include "vmx.h"
#include "compat.h"

static atomic_t vmx_enable_failed;

static DECLARE_BITMAP(vmx_vpid_bitmap, VMX_NR_VPIDS);
static DEFINE_SPINLOCK(vmx_vpid_lock);

static unsigned long *msr_bitmap;

#define NUM_SYSCALLS 312

typedef void (*sys_call_ptr_t)(void);
static sys_call_ptr_t dune_syscall_tbl[NUM_SYSCALLS] __cacheline_aligned;

static DEFINE_PER_CPU(struct vmcs *, vmxarea);
static DEFINE_PER_CPU(struct desc_ptr, host_gdt);
static DEFINE_PER_CPU(int, vmx_enabled);
DEFINE_PER_CPU(struct vmx_vcpu *, local_vcpu);

static struct vmcs_config {
	int size;
	int order;
	u32 revision_id;
	u32 pin_based_exec_ctrl;
	u32 cpu_based_exec_ctrl;
	u32 cpu_based_2nd_exec_ctrl;
	u32 vmexit_ctrl;
	u32 vmentry_ctrl;
} vmcs_config;

struct vmx_capability vmx_capability;

static inline bool cpu_has_secondary_exec_ctrls(void)
{
	return vmcs_config.cpu_based_exec_ctrl &
		CPU_BASED_ACTIVATE_SECONDARY_CONTROLS;
}

static inline bool cpu_has_vmx_vpid(void)
{
	return vmcs_config.cpu_based_2nd_exec_ctrl &
		SECONDARY_EXEC_ENABLE_VPID;
}

static inline bool cpu_has_vmx_invpcid(void)
{
	return vmcs_config.cpu_based_2nd_exec_ctrl &
		SECONDARY_EXEC_ENABLE_INVPCID;
}

static inline bool cpu_has_vmx_invvpid_single(void)
{
	return vmx_capability.vpid & VMX_VPID_EXTENT_SINGLE_CONTEXT_BIT;
}

static inline bool cpu_has_vmx_invvpid_global(void)
{
	return vmx_capability.vpid & VMX_VPID_EXTENT_GLOBAL_CONTEXT_BIT;
}

static inline bool cpu_has_vmx_ept(void)
{
	return vmcs_config.cpu_based_2nd_exec_ctrl &
		SECONDARY_EXEC_ENABLE_EPT;
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

static inline bool cpu_has_vmx_ept_ad_bits(void)
{
	return vmx_capability.ept & VMX_EPT_AD_BIT;
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

static inline void __vmxon(u64 addr)
{
	asm volatile (ASM_VMX_VMXON_RAX
			: : "a"(&addr), "m"(addr)
			: "memory", "cc");
}

static inline void __vmxoff(void)
{
	asm volatile (ASM_VMX_VMXOFF : : : "cc");
}

static inline void __invvpid(int ext, u16 vpid, gva_t gva)
{
    struct {
	u64 vpid : 16;
	u64 rsvd : 48;
	u64 gva;
    } operand = { vpid, 0, gva };

    asm volatile (ASM_VMX_INVVPID
		  /* CF==1 or ZF==1 --> rc = -1 */
		  "; ja 1f ; ud2 ; 1:"
		  : : "a"(&operand), "c"(ext) : "cc", "memory");
}

static inline void vpid_sync_vcpu_single(u16 vpid)
{
	if (vpid == 0)
		return;

	if (cpu_has_vmx_invvpid_single())
		__invvpid(VMX_VPID_EXTENT_SINGLE_CONTEXT, vpid, 0);
}

static inline void vpid_sync_vcpu_global(void)
{
	if (cpu_has_vmx_invvpid_global())
		__invvpid(VMX_VPID_EXTENT_ALL_CONTEXT, 0, 0);
}

static inline void vpid_sync_context(u16 vpid)
{
	if (cpu_has_vmx_invvpid_single())
		vpid_sync_vcpu_single(vpid);
	else
		vpid_sync_vcpu_global();
}

static void vmcs_clear(struct vmcs *vmcs)
{
	u64 phys_addr = __pa(vmcs);
	u8 error;

	asm volatile (ASM_VMX_VMCLEAR_RAX "; setna %0"
		      : "=qm"(error) : "a"(&phys_addr), "m"(phys_addr)
		      : "cc", "memory");
	if (error)
		printk(KERN_ERR "kvm: vmclear fail: %p/%llx\n",
		       vmcs, phys_addr);
}

static void vmcs_load(struct vmcs *vmcs)
{
	u64 phys_addr = __pa(vmcs);
	u8 error;

	asm volatile (ASM_VMX_VMPTRLD_RAX "; setna %0"
			: "=qm"(error) : "a"(&phys_addr), "m"(phys_addr)
			: "cc", "memory");
	if (error)
		printk(KERN_ERR "vmx: vmptrld %p/%llx failed\n",
		       vmcs, phys_addr);
}

static __always_inline u16 vmcs_read16(unsigned long field)
{
	return vmcs_readl(field);
}

static __always_inline u32 vmcs_read32(unsigned long field)
{
	return vmcs_readl(field);
}

static __always_inline u64 vmcs_read64(unsigned long field)
{
#ifdef CONFIG_X86_64
	return vmcs_readl(field);
#else
	return vmcs_readl(field) | ((u64)vmcs_readl(field+1) << 32);
#endif
}

static noinline void vmwrite_error(unsigned long field, unsigned long value)
{
	printk(KERN_ERR "vmwrite error: reg %lx value %lx (err %d)\n",
	       field, value, vmcs_read32(VM_INSTRUCTION_ERROR));
	dump_stack();
}

static void vmcs_writel(unsigned long field, unsigned long value)
{
	u8 error;

	asm volatile (ASM_VMX_VMWRITE_RAX_RDX "; setna %0"
		       : "=q"(error) : "a"(value), "d"(field) : "cc");
	if (unlikely(error))
		vmwrite_error(field, value);
}

static void vmcs_write16(unsigned long field, u16 value)
{
	vmcs_writel(field, value);
}

static void vmcs_write32(unsigned long field, u32 value)
{
	vmcs_writel(field, value);
}

static void vmcs_write64(unsigned long field, u64 value)
{
	vmcs_writel(field, value);
#ifndef CONFIG_X86_64
	asm volatile ("");
	vmcs_writel(field+1, value >> 32);
#endif
}

static __init int adjust_vmx_controls(u32 ctl_min, u32 ctl_opt,
				      u32 msr, u32 *result)
{
	u32 vmx_msr_low, vmx_msr_high;
	u32 ctl = ctl_min | ctl_opt;

	rdmsr(msr, vmx_msr_low, vmx_msr_high);

	ctl &= vmx_msr_high; /* bit == 0 in high word ==> must be zero */
	ctl |= vmx_msr_low;  /* bit == 1 in low word  ==> must be one  */

	/* Ensure minimum (required) set of control bits are supported. */
	if (ctl_min & ~ctl)
		return -EIO;

	*result = ctl;
	return 0;
}

static __init bool allow_1_setting(u32 msr, u32 ctl)
{
	u32 vmx_msr_low, vmx_msr_high;

	rdmsr(msr, vmx_msr_low, vmx_msr_high);
	return vmx_msr_high & ctl;
}

static __init int setup_vmcs_config(struct vmcs_config *vmcs_conf)
{
	u32 vmx_msr_low, vmx_msr_high;
	u32 min, opt, min2, opt2;
	u32 _pin_based_exec_control = 0;
	u32 _cpu_based_exec_control = 0;
	u32 _cpu_based_2nd_exec_control = 0;
	u32 _vmexit_control = 0;
	u32 _vmentry_control = 0;

	min = PIN_BASED_EXT_INTR_MASK | PIN_BASED_NMI_EXITING;
	opt = PIN_BASED_VIRTUAL_NMIS;
	if (adjust_vmx_controls(min, opt, MSR_IA32_VMX_PINBASED_CTLS,
				&_pin_based_exec_control) < 0)
		return -EIO;

	min =
#ifdef CONFIG_X86_64
	      CPU_BASED_CR8_LOAD_EXITING |
	      CPU_BASED_CR8_STORE_EXITING |
#endif
	      CPU_BASED_CR3_LOAD_EXITING |
	      CPU_BASED_CR3_STORE_EXITING |
	      CPU_BASED_MOV_DR_EXITING |
	      CPU_BASED_USE_TSC_OFFSETING |
	      CPU_BASED_INVLPG_EXITING;

	opt = CPU_BASED_TPR_SHADOW |
	      CPU_BASED_USE_MSR_BITMAPS |
	      CPU_BASED_ACTIVATE_SECONDARY_CONTROLS;
	if (adjust_vmx_controls(min, opt, MSR_IA32_VMX_PROCBASED_CTLS,
				&_cpu_based_exec_control) < 0)
		return -EIO;
#ifdef CONFIG_X86_64
	if ((_cpu_based_exec_control & CPU_BASED_TPR_SHADOW))
		_cpu_based_exec_control &= ~CPU_BASED_CR8_LOAD_EXITING &
					   ~CPU_BASED_CR8_STORE_EXITING;
#endif
	if (_cpu_based_exec_control & CPU_BASED_ACTIVATE_SECONDARY_CONTROLS) {
		min2 = 0;
		opt2 =  SECONDARY_EXEC_WBINVD_EXITING |
			SECONDARY_EXEC_ENABLE_VPID |
			SECONDARY_EXEC_ENABLE_EPT |
			SECONDARY_EXEC_RDTSCP |
			SECONDARY_EXEC_ENABLE_INVPCID;
		if (adjust_vmx_controls(min2, opt2,
					MSR_IA32_VMX_PROCBASED_CTLS2,
					&_cpu_based_2nd_exec_control) < 0)
			return -EIO;
	}
#ifndef CONFIG_X86_64
	if (!(_cpu_based_2nd_exec_control &
				SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES))
		_cpu_based_exec_control &= ~CPU_BASED_TPR_SHADOW;
#endif
	if (_cpu_based_2nd_exec_control & SECONDARY_EXEC_ENABLE_EPT) {
		/* CR3 accesses and invlpg don't need to cause VM Exits when EPT
		   enabled */
		_cpu_based_exec_control &= ~(CPU_BASED_CR3_LOAD_EXITING |
					     CPU_BASED_CR3_STORE_EXITING |
					     CPU_BASED_INVLPG_EXITING);
		rdmsr(MSR_IA32_VMX_EPT_VPID_CAP,
		      vmx_capability.ept, vmx_capability.vpid);
	}

	min = 0;
#ifdef CONFIG_X86_64
	min |= VM_EXIT_HOST_ADDR_SPACE_SIZE;
#endif
//	opt = VM_EXIT_SAVE_IA32_PAT | VM_EXIT_LOAD_IA32_PAT;
	opt = 0;
	if (adjust_vmx_controls(min, opt, MSR_IA32_VMX_EXIT_CTLS,
				&_vmexit_control) < 0)
		return -EIO;

	min = 0;
//	opt = VM_ENTRY_LOAD_IA32_PAT;
	opt = 0;
	if (adjust_vmx_controls(min, opt, MSR_IA32_VMX_ENTRY_CTLS,
				&_vmentry_control) < 0)
		return -EIO;

	rdmsr(MSR_IA32_VMX_BASIC, vmx_msr_low, vmx_msr_high);

	/* IA-32 SDM Vol 3B: VMCS size is never greater than 4kB. */
	if ((vmx_msr_high & 0x1fff) > PAGE_SIZE)
		return -EIO;

#ifdef CONFIG_X86_64
	/* IA-32 SDM Vol 3B: 64-bit CPUs always have VMX_BASIC_MSR[48]==0. */
	if (vmx_msr_high & (1u<<16))
		return -EIO;
#endif

	/* Require Write-Back (WB) memory type for VMCS accesses. */
	if (((vmx_msr_high >> 18) & 15) != 6)
		return -EIO;

	vmcs_conf->size = vmx_msr_high & 0x1fff;
	vmcs_conf->order = get_order(vmcs_config.size);
	vmcs_conf->revision_id = vmx_msr_low;

	vmcs_conf->pin_based_exec_ctrl = _pin_based_exec_control;
	vmcs_conf->cpu_based_exec_ctrl = _cpu_based_exec_control;
	vmcs_conf->cpu_based_2nd_exec_ctrl = _cpu_based_2nd_exec_control;
	vmcs_conf->vmexit_ctrl         = _vmexit_control;
	vmcs_conf->vmentry_ctrl        = _vmentry_control;

	vmx_capability.has_load_efer =
		allow_1_setting(MSR_IA32_VMX_ENTRY_CTLS,
				VM_ENTRY_LOAD_IA32_EFER)
		&& allow_1_setting(MSR_IA32_VMX_EXIT_CTLS,
				   VM_EXIT_LOAD_IA32_EFER);

	return 0;
}

static struct vmcs *__vmx_alloc_vmcs(int cpu)
{
	int node = cpu_to_node(cpu);
	struct page *pages;
	struct vmcs *vmcs;

	pages = alloc_pages_exact_node(node, GFP_KERNEL, vmcs_config.order);
	if (!pages)
		return NULL;
	vmcs = page_address(pages);
	memset(vmcs, 0, vmcs_config.size);
	vmcs->revision_id = vmcs_config.revision_id; /* vmcs revision id */
	return vmcs;
}

/**
 * vmx_alloc_vmcs - allocates a VMCS region
 *
 * NOTE: Assumes the new region will be used by the current CPU.
 *
 * Returns a valid VMCS region.
 */
static struct vmcs *vmx_alloc_vmcs(void)
{
	return __vmx_alloc_vmcs(raw_smp_processor_id());
}

/**
 * vmx_free_vmcs - frees a VMCS region
 */
static void vmx_free_vmcs(struct vmcs *vmcs)
{
	free_pages((unsigned long)vmcs, vmcs_config.order);
}

/*
 * Set up the vmcs's constant host-state fields, i.e., host-state fields that
 * will not change in the lifetime of the guest.
 * Note that host-state that does change is set elsewhere. E.g., host-state
 * that is set differently for each CPU is set in vmx_vcpu_load(), not here.
 */
static void vmx_setup_constant_host_state(void)
{
	u32 low32, high32;
	unsigned long tmpl;
	struct desc_ptr dt;

	vmcs_writel(HOST_CR0, read_cr0() & ~X86_CR0_TS);  /* 22.2.3 */
	vmcs_writel(HOST_CR4, read_cr4());  /* 22.2.3, 22.2.5 */
	vmcs_writel(HOST_CR3, read_cr3());  /* 22.2.3 */

	vmcs_write16(HOST_CS_SELECTOR, __KERNEL_CS);  /* 22.2.4 */
	vmcs_write16(HOST_DS_SELECTOR, __KERNEL_DS);  /* 22.2.4 */
	vmcs_write16(HOST_ES_SELECTOR, __KERNEL_DS);  /* 22.2.4 */
	vmcs_write16(HOST_SS_SELECTOR, __KERNEL_DS);  /* 22.2.4 */
	vmcs_write16(HOST_TR_SELECTOR, GDT_ENTRY_TSS*8);  /* 22.2.4 */

	native_store_idt(&dt);
	vmcs_writel(HOST_IDTR_BASE, dt.address);   /* 22.2.4 */

	asm("mov $.Lkvm_vmx_return, %0" : "=r"(tmpl));
	vmcs_writel(HOST_RIP, tmpl); /* 22.2.5 */

	rdmsr(MSR_IA32_SYSENTER_CS, low32, high32);
	vmcs_write32(HOST_IA32_SYSENTER_CS, low32);
	rdmsrl(MSR_IA32_SYSENTER_EIP, tmpl);
	vmcs_writel(HOST_IA32_SYSENTER_EIP, tmpl);   /* 22.2.3 */

	rdmsr(MSR_EFER, low32, high32);
	vmcs_write32(HOST_IA32_EFER, low32);

	if (vmcs_config.vmexit_ctrl & VM_EXIT_LOAD_IA32_PAT) {
		rdmsr(MSR_IA32_CR_PAT, low32, high32);
		vmcs_write64(HOST_IA32_PAT, low32 | ((u64) high32 << 32));
	}

	vmcs_write16(HOST_FS_SELECTOR, 0);            /* 22.2.4 */
	vmcs_write16(HOST_GS_SELECTOR, 0);            /* 22.2.4 */

#ifdef CONFIG_X86_64
	rdmsrl(MSR_FS_BASE, tmpl);
	vmcs_writel(HOST_FS_BASE, tmpl); /* 22.2.4 */
	rdmsrl(MSR_GS_BASE, tmpl);
	vmcs_writel(HOST_GS_BASE, tmpl); /* 22.2.4 */
#else
	vmcs_writel(HOST_FS_BASE, 0); /* 22.2.4 */
	vmcs_writel(HOST_GS_BASE, 0); /* 22.2.4 */
#endif
}

static inline u16 vmx_read_ldt(void)
{
	u16 ldt;
	asm("sldt %0" : "=g"(ldt));
	return ldt;
}

static unsigned long segment_base(u16 selector)
{
	struct desc_ptr *gdt = &__get_cpu_var(host_gdt);
	struct desc_struct *d;
	unsigned long table_base;
	unsigned long v;

	if (!(selector & ~3))
		return 0;

	table_base = gdt->address;

	if (selector & 4) {           /* from ldt */
		u16 ldt_selector = vmx_read_ldt();

		if (!(ldt_selector & ~3))
			return 0;

		table_base = segment_base(ldt_selector);
	}
	d = (struct desc_struct *)(table_base + (selector & ~7));
	v = get_desc_base(d);
#ifdef CONFIG_X86_64
       if (d->s == 0 && (d->type == 2 || d->type == 9 || d->type == 11))
               v |= ((unsigned long)((struct ldttss_desc64 *)d)->base3) << 32;
#endif
	return v;
}

static inline unsigned long vmx_read_tr_base(void)
{
	u16 tr;
	asm("str %0" : "=g"(tr));
	return segment_base(tr);
}

static void __vmx_setup_cpu(void)
{
	struct desc_ptr *gdt = &__get_cpu_var(host_gdt);
	unsigned long sysenter_esp;
	unsigned long tmpl;

	/*
	 * Linux uses per-cpu TSS and GDT, so set these when switching
	 * processors.
	 */
	vmcs_writel(HOST_TR_BASE, vmx_read_tr_base()); /* 22.2.4 */
	vmcs_writel(HOST_GDTR_BASE, gdt->address);   /* 22.2.4 */

	rdmsrl(MSR_IA32_SYSENTER_ESP, sysenter_esp);
	vmcs_writel(HOST_IA32_SYSENTER_ESP, sysenter_esp); /* 22.2.3 */

	rdmsrl(MSR_FS_BASE, tmpl);
	vmcs_writel(HOST_FS_BASE, tmpl); /* 22.2.4 */
	rdmsrl(MSR_GS_BASE, tmpl);
	vmcs_writel(HOST_GS_BASE, tmpl); /* 22.2.4 */
}

static void __vmx_get_cpu_helper(void *ptr)
{
	struct vmx_vcpu *vcpu = ptr;

	BUG_ON(raw_smp_processor_id() != vcpu->cpu);
	vmcs_clear(vcpu->vmcs);
	if (__get_cpu_var(local_vcpu) == vcpu)
		__get_cpu_var(local_vcpu) = NULL;
}

/**
 * vmx_get_cpu - called before using a cpu
 * @vcpu: VCPU that will be loaded.
 *
 * Disables preemption. Call vmx_put_cpu() when finished.
 */
static void vmx_get_cpu(struct vmx_vcpu *vcpu)
{
	int cur_cpu = get_cpu();

	if (__get_cpu_var(local_vcpu) != vcpu) {
		__get_cpu_var(local_vcpu) = vcpu;

		if (vcpu->cpu != cur_cpu) {
			if (vcpu->cpu >= 0)
				smp_call_function_single(vcpu->cpu,
					__vmx_get_cpu_helper, (void *) vcpu, 1);
			else
				vmcs_clear(vcpu->vmcs);

			vpid_sync_context(vcpu->vpid);
			ept_sync_context(vcpu->eptp);

			vcpu->launched = 0;
			vmcs_load(vcpu->vmcs);
			__vmx_setup_cpu();
			vcpu->cpu = cur_cpu;
		} else {
			vmcs_load(vcpu->vmcs);
		}
	}
}

/**
 * vmx_put_cpu - called after using a cpu
 * @vcpu: VCPU that was loaded.
 */
static void vmx_put_cpu(struct vmx_vcpu *vcpu)
{
	put_cpu();
}

static void __vmx_sync_helper(void *ptr)
{
	struct vmx_vcpu *vcpu = ptr;

	ept_sync_context(vcpu->eptp);
}

struct sync_addr_args {
	struct vmx_vcpu *vcpu;
	gpa_t gpa;
};

static void __vmx_sync_individual_addr_helper(void *ptr)
{
	struct sync_addr_args *args = ptr;

	ept_sync_individual_addr(args->vcpu->eptp,
				 (args->gpa & ~(PAGE_SIZE - 1)));
}

/**
 * vmx_ept_sync_global - used to evict everything in the EPT
 * @vcpu: the vcpu
 */
void vmx_ept_sync_vcpu(struct vmx_vcpu *vcpu)
{
	smp_call_function_single(vcpu->cpu,
		__vmx_sync_helper, (void *) vcpu, 1);
}

/**
 * vmx_ept_sync_individual_addr - used to evict an individual address
 * @vcpu: the vcpu
 * @gpa: the guest-physical address
 */
void vmx_ept_sync_individual_addr(struct vmx_vcpu *vcpu, gpa_t gpa)
{
	struct sync_addr_args args;
	args.vcpu = vcpu;
	args.gpa = gpa;

	smp_call_function_single(vcpu->cpu,
		__vmx_sync_individual_addr_helper, (void *) &args, 1);
}

#define STACK_DEPTH 12

/**
 * vmx_dump_cpu - prints the CPU state
 * @vcpu: VCPU to print
 */
static void vmx_dump_cpu(struct vmx_vcpu *vcpu)
{
	unsigned long flags;
	int i;
	unsigned long *sp, val;

	vmx_get_cpu(vcpu);
	vcpu->regs[VCPU_REGS_RIP] = vmcs_readl(GUEST_RIP);
	vcpu->regs[VCPU_REGS_RSP] = vmcs_readl(GUEST_RSP);
	flags = vmcs_readl(GUEST_RFLAGS);
	vmx_put_cpu(vcpu);

	printk(KERN_INFO "vmx: --- Begin VCPU Dump ---\n");
	printk(KERN_INFO "vmx: CPU %d VPID %d\n", vcpu->cpu, vcpu->vpid);
	printk(KERN_INFO "vmx: RIP 0x%016llx RFLAGS 0x%08lx\n",
	       vcpu->regs[VCPU_REGS_RIP], flags);
	printk(KERN_INFO "vmx: RAX 0x%016llx RCX 0x%016llx\n",
			vcpu->regs[VCPU_REGS_RAX], vcpu->regs[VCPU_REGS_RCX]);
	printk(KERN_INFO "vmx: RDX 0x%016llx RBX 0x%016llx\n",
			vcpu->regs[VCPU_REGS_RDX], vcpu->regs[VCPU_REGS_RBX]);
	printk(KERN_INFO "vmx: RSP 0x%016llx RBP 0x%016llx\n",
			vcpu->regs[VCPU_REGS_RSP], vcpu->regs[VCPU_REGS_RBP]);
	printk(KERN_INFO "vmx: RSI 0x%016llx RDI 0x%016llx\n",
			vcpu->regs[VCPU_REGS_RSI], vcpu->regs[VCPU_REGS_RDI]);
	printk(KERN_INFO "vmx: R8  0x%016llx R9  0x%016llx\n",
			vcpu->regs[VCPU_REGS_R8], vcpu->regs[VCPU_REGS_R9]);
	printk(KERN_INFO "vmx: R10 0x%016llx R11 0x%016llx\n",
			vcpu->regs[VCPU_REGS_R10], vcpu->regs[VCPU_REGS_R11]);
	printk(KERN_INFO "vmx: R12 0x%016llx R13 0x%016llx\n",
			vcpu->regs[VCPU_REGS_R12], vcpu->regs[VCPU_REGS_R13]);
	printk(KERN_INFO "vmx: R14 0x%016llx R15 0x%016llx\n",
			vcpu->regs[VCPU_REGS_R14], vcpu->regs[VCPU_REGS_R15]);

	printk(KERN_INFO "vmx: Dumping Stack Contents...\n");
	sp = (unsigned long *) vcpu->regs[VCPU_REGS_RSP];
	for (i = 0; i < STACK_DEPTH; i++)
		if (get_user(val, &sp[i]))
			printk(KERN_INFO "vmx: RSP%+-3ld ?\n",
				i * sizeof(long));
		else
			printk(KERN_INFO "vmx: RSP%+-3ld 0x%016lx\n",
				i * sizeof(long), val);

	printk(KERN_INFO "vmx: --- End VCPU Dump ---\n");
}

static u64 construct_eptp(unsigned long root_hpa)
{
	u64 eptp;

	/* TODO write the value reading from MSR */
	eptp = VMX_EPT_DEFAULT_MT |
		VMX_EPT_DEFAULT_GAW << VMX_EPT_GAW_EPTP_SHIFT;
	if (cpu_has_vmx_ept_ad_bits())
		eptp |= VMX_EPT_AD_ENABLE_BIT;
	eptp |= (root_hpa & PAGE_MASK);

	return eptp;
}

/**
 * vmx_setup_initial_guest_state - configures the initial state of guest registers
 */
static void vmx_setup_initial_guest_state(struct dune_config *conf)
{
	unsigned long tmpl;
	unsigned long cr4 = X86_CR4_PAE | X86_CR4_VMXE | X86_CR4_OSXMMEXCPT |
			    X86_CR4_PGE | X86_CR4_OSFXSR;
	if (boot_cpu_has(X86_FEATURE_PCID))
		cr4 |= X86_CR4_PCIDE;
	if (boot_cpu_has(X86_FEATURE_OSXSAVE))
		cr4 |= X86_CR4_OSXSAVE;
	if (boot_cpu_has(X86_FEATURE_FSGSBASE))
		cr4 |= X86_CR4_FSGSBASE;

	/* configure control and data registers */
	vmcs_writel(GUEST_CR0, X86_CR0_PG | X86_CR0_PE | X86_CR0_WP |
			       X86_CR0_MP | X86_CR0_ET | X86_CR0_NE);
	vmcs_writel(CR0_READ_SHADOW, X86_CR0_PG | X86_CR0_PE | X86_CR0_WP |
				     X86_CR0_MP | X86_CR0_ET | X86_CR0_NE);
	vmcs_writel(GUEST_CR3, conf->cr3);
	vmcs_writel(GUEST_CR4, cr4);
	vmcs_writel(CR4_READ_SHADOW, cr4);
	vmcs_writel(GUEST_IA32_EFER, EFER_LME | EFER_LMA |
				     EFER_SCE | EFER_FFXSR);
	vmcs_writel(GUEST_GDTR_BASE, 0);
	vmcs_writel(GUEST_GDTR_LIMIT, 0);
	vmcs_writel(GUEST_IDTR_BASE, 0);
	vmcs_writel(GUEST_IDTR_LIMIT, 0);
	vmcs_writel(GUEST_RIP, conf->rip);
	vmcs_writel(GUEST_RSP, conf->rsp);
	vmcs_writel(GUEST_RFLAGS, 0x02);
	vmcs_writel(GUEST_DR7, 0);

	/* guest segment bases */
	vmcs_writel(GUEST_CS_BASE, 0);
	vmcs_writel(GUEST_DS_BASE, 0);
	vmcs_writel(GUEST_ES_BASE, 0);
	vmcs_writel(GUEST_GS_BASE, 0);
	vmcs_writel(GUEST_SS_BASE, 0);
	rdmsrl(MSR_FS_BASE, tmpl);
	vmcs_writel(GUEST_FS_BASE, tmpl);

	/* guest segment access rights */
	vmcs_writel(GUEST_CS_AR_BYTES, 0xA09B);
	vmcs_writel(GUEST_DS_AR_BYTES, 0xA093);
	vmcs_writel(GUEST_ES_AR_BYTES, 0xA093);
	vmcs_writel(GUEST_FS_AR_BYTES, 0xA093);
	vmcs_writel(GUEST_GS_AR_BYTES, 0xA093);
	vmcs_writel(GUEST_SS_AR_BYTES, 0xA093);

	/* guest segment limits */
	vmcs_write32(GUEST_CS_LIMIT, 0xFFFFFFFF);
	vmcs_write32(GUEST_DS_LIMIT, 0xFFFFFFFF);
	vmcs_write32(GUEST_ES_LIMIT, 0xFFFFFFFF);
	vmcs_write32(GUEST_FS_LIMIT, 0xFFFFFFFF);
	vmcs_write32(GUEST_GS_LIMIT, 0xFFFFFFFF);
	vmcs_write32(GUEST_SS_LIMIT, 0xFFFFFFFF);

	/* configure segment selectors */
	vmcs_write16(GUEST_CS_SELECTOR, 0);
	vmcs_write16(GUEST_DS_SELECTOR, 0);
	vmcs_write16(GUEST_ES_SELECTOR, 0);
	vmcs_write16(GUEST_FS_SELECTOR, 0);
	vmcs_write16(GUEST_GS_SELECTOR, 0);
	vmcs_write16(GUEST_SS_SELECTOR, 0);
	vmcs_write16(GUEST_TR_SELECTOR, 0);

	/* guest LDTR */
	vmcs_write16(GUEST_LDTR_SELECTOR, 0);
	vmcs_writel(GUEST_LDTR_AR_BYTES, 0x0082);
	vmcs_writel(GUEST_LDTR_BASE, 0);
	vmcs_writel(GUEST_LDTR_LIMIT, 0);

	/* guest TSS */
	vmcs_writel(GUEST_TR_BASE, 0);
	vmcs_writel(GUEST_TR_AR_BYTES, 0x0080 | AR_TYPE_BUSY_64_TSS);
	vmcs_writel(GUEST_TR_LIMIT, 0xff);

	/* initialize sysenter */
	vmcs_write32(GUEST_SYSENTER_CS, 0);
	vmcs_writel(GUEST_SYSENTER_ESP, 0);
	vmcs_writel(GUEST_SYSENTER_EIP, 0);

	/* other random initialization */
	vmcs_write32(GUEST_ACTIVITY_STATE, GUEST_ACTIVITY_ACTIVE);
	vmcs_write32(GUEST_INTERRUPTIBILITY_INFO, 0);
	vmcs_write32(GUEST_PENDING_DBG_EXCEPTIONS, 0);
	vmcs_write64(GUEST_IA32_DEBUGCTL, 0);
	vmcs_write32(VM_ENTRY_INTR_INFO_FIELD, 0);  /* 22.2.1 */
}

static void __vmx_disable_intercept_for_msr(unsigned long *msr_bitmap, u32 msr)
{
	int f = sizeof(unsigned long);
	/*
	 * See Intel PRM Vol. 3, 20.6.9 (MSR-Bitmap Address). Early manuals
	 * have the write-low and read-high bitmap offsets the wrong way round.
	 * We can control MSRs 0x00000000-0x00001fff and 0xc0000000-0xc0001fff.
	 */
	if (msr <= 0x1fff) {
		__clear_bit(msr, msr_bitmap + 0x000 / f); /* read-low */
		__clear_bit(msr, msr_bitmap + 0x800 / f); /* write-low */
	} else if ((msr >= 0xc0000000) && (msr <= 0xc0001fff)) {
		msr &= 0x1fff;
		__clear_bit(msr, msr_bitmap + 0x400 / f); /* read-high */
		__clear_bit(msr, msr_bitmap + 0xc00 / f); /* write-high */
	}
}

static void setup_msr(struct vmx_vcpu *vcpu)
{
	int set[] = { MSR_LSTAR };
	struct vmx_msr_entry *e;
	int sz = sizeof(set) / sizeof(*set);
	int i;

	sz = 0;

	BUILD_BUG_ON(sz > NR_AUTOLOAD_MSRS);

	vcpu->msr_autoload.nr = sz;

	/* XXX enable only MSRs in set */
	vmcs_write64(MSR_BITMAP, __pa(msr_bitmap));

	vmcs_write32(VM_EXIT_MSR_STORE_COUNT, vcpu->msr_autoload.nr);
	vmcs_write32(VM_EXIT_MSR_LOAD_COUNT, vcpu->msr_autoload.nr);
	vmcs_write32(VM_ENTRY_MSR_LOAD_COUNT, vcpu->msr_autoload.nr);

	vmcs_write64(VM_EXIT_MSR_LOAD_ADDR, __pa(vcpu->msr_autoload.host));
	vmcs_write64(VM_EXIT_MSR_STORE_ADDR, __pa(vcpu->msr_autoload.guest));
	vmcs_write64(VM_ENTRY_MSR_LOAD_ADDR, __pa(vcpu->msr_autoload.guest));

	for (i = 0; i < sz; i++) {
		uint64_t val;

		e = &vcpu->msr_autoload.host[i];
		e->index = set[i];
		rdmsrl(e->index, val);
		e->value = val;

		e = &vcpu->msr_autoload.guest[i];
		e->index = set[i];
	}
}

/**
 *  vmx_setup_vmcs - configures the vmcs with starting parameters
 */
static void vmx_setup_vmcs(struct vmx_vcpu *vcpu)
{
	vmcs_write16(VIRTUAL_PROCESSOR_ID, vcpu->vpid);
	vmcs_write64(VMCS_LINK_POINTER, -1ull); /* 22.3.1.5 */

	/* Control */
	vmcs_write32(PIN_BASED_VM_EXEC_CONTROL,
		vmcs_config.pin_based_exec_ctrl);

	vmcs_write32(CPU_BASED_VM_EXEC_CONTROL,
		vmcs_config.cpu_based_exec_ctrl);

	if (cpu_has_secondary_exec_ctrls()) {
		vmcs_write32(SECONDARY_VM_EXEC_CONTROL,
			     vmcs_config.cpu_based_2nd_exec_ctrl);
	}

	vmcs_write64(EPT_POINTER, vcpu->eptp);

	vmcs_write32(PAGE_FAULT_ERROR_CODE_MASK, 0);
	vmcs_write32(PAGE_FAULT_ERROR_CODE_MATCH, 0);
	vmcs_write32(CR3_TARGET_COUNT, 0);           /* 22.2.1 */

	setup_msr(vcpu);
#if 0
	if (vmcs_config.vmentry_ctrl & VM_ENTRY_LOAD_IA32_PAT) {
		u32 msr_low, msr_high;
		u64 host_pat;
		rdmsr(MSR_IA32_CR_PAT, msr_low, msr_high);
		host_pat = msr_low | ((u64) msr_high << 32);
		/* Write the default value follow host pat */
		vmcs_write64(GUEST_IA32_PAT, host_pat);
		/* Keep arch.pat sync with GUEST_IA32_PAT */
		vmx->vcpu.arch.pat = host_pat;
	}

	for (i = 0; i < NR_VMX_MSR; ++i) {
		u32 index = vmx_msr_index[i];
		u32 data_low, data_high;
		int j = vmx->nmsrs;

		if (rdmsr_safe(index, &data_low, &data_high) < 0)
			continue;
		if (wrmsr_safe(index, data_low, data_high) < 0)
			continue;
		vmx->guest_msrs[j].index = i;
		vmx->guest_msrs[j].data = 0;
		vmx->guest_msrs[j].mask = -1ull;
		++vmx->nmsrs;
	}
#endif

	vmcs_config.vmentry_ctrl |= VM_ENTRY_IA32E_MODE;

	vmcs_write32(VM_EXIT_CONTROLS, vmcs_config.vmexit_ctrl);
	vmcs_write32(VM_ENTRY_CONTROLS, vmcs_config.vmentry_ctrl);

	vmcs_writel(CR0_GUEST_HOST_MASK, ~0ul);
	vmcs_writel(CR4_GUEST_HOST_MASK, ~0ul);

	//kvm_write_tsc(&vmx->vcpu, 0);
	vmcs_writel(TSC_OFFSET, 0);

	vmx_setup_constant_host_state();
}

/**
 * vmx_allocate_vpid - reserves a vpid and sets it in the VCPU
 * @vmx: the VCPU
 */
static int vmx_allocate_vpid(struct vmx_vcpu *vmx)
{
	int vpid;

	vmx->vpid = 0;

	spin_lock(&vmx_vpid_lock);
	vpid = find_first_zero_bit(vmx_vpid_bitmap, VMX_NR_VPIDS);
	if (vpid < VMX_NR_VPIDS) {
		vmx->vpid = vpid;
		__set_bit(vpid, vmx_vpid_bitmap);
	}
	spin_unlock(&vmx_vpid_lock);

	return vpid >= VMX_NR_VPIDS;
}

/**
 * vmx_free_vpid - frees a vpid
 * @vmx: the VCPU
 */
static void vmx_free_vpid(struct vmx_vcpu *vmx)
{
	spin_lock(&vmx_vpid_lock);
	if (vmx->vpid != 0)
		__clear_bit(vmx->vpid, vmx_vpid_bitmap);
	spin_unlock(&vmx_vpid_lock);
}

/**
 * vmx_create_vcpu - allocates and initializes a new virtual cpu
 *
 * Returns: A new VCPU structure
 */
static struct vmx_vcpu * vmx_create_vcpu(struct dune_config *conf)
{
	struct vmx_vcpu *vcpu = kmalloc(sizeof(struct vmx_vcpu), GFP_KERNEL);
	if (!vcpu)
		return NULL;

	memset(vcpu, 0, sizeof(*vcpu));

	vcpu->vmcs = vmx_alloc_vmcs();
	if (!vcpu->vmcs)
		goto fail_vmcs;

	if (vmx_allocate_vpid(vcpu))
		goto fail_vpid;

	vcpu->cpu = -1;
	vcpu->syscall_tbl = (void *) &dune_syscall_tbl;

	spin_lock_init(&vcpu->ept_lock);
	if (vmx_init_ept(vcpu))
		goto fail_ept;
	vcpu->eptp = construct_eptp(vcpu->ept_root);

	vmx_get_cpu(vcpu);
	vmx_setup_vmcs(vcpu);
	vmx_setup_initial_guest_state(conf);
	vmx_put_cpu(vcpu);

	if (cpu_has_vmx_ept_ad_bits()) {
		vcpu->ept_ad_enabled = true;
		printk(KERN_INFO "vmx: enabled EPT A/D bits");
	}
	if (vmx_create_ept(vcpu))
		goto fail_ept;

	return vcpu;

fail_ept:
	vmx_free_vpid(vcpu);
fail_vpid:
	vmx_free_vmcs(vcpu->vmcs);
fail_vmcs:
	kfree(vcpu);
	return NULL;
}

/**
 * vmx_destroy_vcpu - destroys and frees an existing virtual cpu
 * @vcpu: the VCPU to destroy
 */
static void vmx_destroy_vcpu(struct vmx_vcpu *vcpu)
{
	vmx_destroy_ept(vcpu);
	vmx_get_cpu(vcpu);
	ept_sync_context(vcpu->eptp);
	vmcs_clear(vcpu->vmcs);
	__get_cpu_var(local_vcpu) = NULL;
	vmx_put_cpu(vcpu);
	vmx_free_vpid(vcpu);
	vmx_free_vmcs(vcpu->vmcs);
	kfree(vcpu);
}

static int dune_exit(int error_code)
{
	struct vmx_vcpu *vcpu;

	/* FIXME: not totally safe depending on GCC */
	asm("movq %%r11, %0" : "=r"(vcpu));

	vcpu->shutdown = 1;
	vcpu->ret_code = error_code;

	return 0;
}

static int dune_exit_group(int error_code)
{
	/* NOTE: we're supposed to send a signal to other threads before
	 * exiting. Because we don't yet support signals we do nothing
	 * extra for now.
	 */
	struct vmx_vcpu *vcpu;

	/* FIXME: not totally safe depending on GCC */
	asm("movq %%r11, %0" : "=r"(vcpu));

	vcpu->shutdown = 1;
	vcpu->ret_code = error_code;

	return 0;
}

static void make_pt_regs(struct vmx_vcpu *vcpu, struct pt_regs *regs,
			 int sysnr)
{
	regs->ax = sysnr;
	regs->orig_ax = vcpu->regs[VCPU_REGS_RAX];
	regs->bx = vcpu->regs[VCPU_REGS_RBX];
	regs->cx = vcpu->regs[VCPU_REGS_RCX];
	regs->dx = vcpu->regs[VCPU_REGS_RDX];
	regs->si = vcpu->regs[VCPU_REGS_RSI];
	regs->di = vcpu->regs[VCPU_REGS_RDI];
	regs->r8 = vcpu->regs[VCPU_REGS_R8];
	regs->r9 = vcpu->regs[VCPU_REGS_R9];
	regs->r10 = vcpu->regs[VCPU_REGS_R10];
	regs->r11 = vcpu->regs[VCPU_REGS_R11];
	regs->r12 = vcpu->regs[VCPU_REGS_R12];
	regs->r13 = vcpu->regs[VCPU_REGS_R13];
	regs->r14 = vcpu->regs[VCPU_REGS_R14];
	regs->r15 = vcpu->regs[VCPU_REGS_R15];
	regs->bp = vcpu->regs[VCPU_REGS_RBP];

	vmx_get_cpu(vcpu);
	regs->ip = vmcs_readl(GUEST_RIP);
	regs->sp = vmcs_readl(GUEST_RSP);
	/* FIXME: do we need to set up other flags? */
	regs->flags = (vmcs_readl(GUEST_RFLAGS) & 0xFF) |
		      X86_EFLAGS_IF | 0x2;
	vmx_put_cpu(vcpu);

	/*
	 * NOTE: Since Dune processes use the kernel's LSTAR
	 * syscall address, we need special logic to handle
	 * certain system calls (fork, clone, etc.) The specifc
	 * issue is that we can not jump to a high address
	 * in a child process since it is not running in Dune.
	 * Our solution is to adopt a special Dune convention
	 * where the desired %RIP address is provided in %RCX.
	 */ 
	if (!(__addr_ok(regs->ip)))
		regs->ip = regs->cx;

	regs->cs = __USER_CS;
	regs->ss = __USER_DS;
}

static long dune_sys_clone(unsigned long clone_flags, unsigned long newsp,
		void __user *parent_tid, void __user *child_tid)
{
	struct vmx_vcpu *vcpu;
	struct pt_regs regs;

	asm("movq %%r11, %0" : "=r"(vcpu));

	make_pt_regs(vcpu, &regs, __NR_clone);
	if (!newsp)
		newsp = regs.sp;

	return dune_do_fork(clone_flags, newsp, &regs, 0, parent_tid, child_tid);
}

static long dune_sys_fork(void)
{
	struct vmx_vcpu *vcpu;
	struct pt_regs regs;
	
	asm("movq %%r11, %0" : "=r"(vcpu));

	make_pt_regs(vcpu, &regs, __NR_fork);

	return dune_do_fork(SIGCHLD, regs.sp, &regs, 0, NULL, NULL);
}

static long dune_sys_vfork(void)
{
	struct vmx_vcpu *vcpu;
	struct pt_regs regs;
	
	asm("movq %%r11, %0" : "=r"(vcpu));

	make_pt_regs(vcpu, &regs, __NR_vfork);

	return dune_do_fork(CLONE_VFORK | CLONE_VM | SIGCHLD, regs.sp,
			    &regs, 0, NULL, NULL);
}

static void vmx_init_syscall(void)
{
	memcpy(dune_syscall_tbl, (void *) SYSCALL_TBL,
	       sizeof(sys_call_ptr_t) * NUM_SYSCALLS);
	
	dune_syscall_tbl[__NR_exit] = (void *) &dune_exit;
	dune_syscall_tbl[__NR_exit_group] = (void *) &dune_exit_group;
	dune_syscall_tbl[__NR_clone] = (void *) &dune_sys_clone;
	dune_syscall_tbl[__NR_fork] = (void *) &dune_sys_fork;
	dune_syscall_tbl[__NR_vfork] = (void *) &dune_sys_vfork;
}

#ifdef CONFIG_X86_64
#define R "r"
#define Q "q"
#else
#define R "e"
#define Q "l"
#endif

/**
 * vmx_run_vcpu - launches the CPU into non-root mode
 * @vcpu: the vmx instance to launch
 */
static int __noclone vmx_run_vcpu(struct vmx_vcpu *vcpu)
{
	asm(
		/* Store host registers */
		"push %%"R"dx; push %%"R"bp;"
		"push %%"R"cx \n\t" /* placeholder for guest rcx */
		"push %%"R"cx \n\t"
		"cmp %%"R"sp, %c[host_rsp](%0) \n\t"
		"je 1f \n\t"
		"mov %%"R"sp, %c[host_rsp](%0) \n\t"
		ASM_VMX_VMWRITE_RSP_RDX "\n\t"
		"1: \n\t"
		/* Reload cr2 if changed */
		"mov %c[cr2](%0), %%"R"ax \n\t"
		"mov %%cr2, %%"R"dx \n\t"
		"cmp %%"R"ax, %%"R"dx \n\t"
		"je 2f \n\t"
		"mov %%"R"ax, %%cr2 \n\t"
		"2: \n\t"
		/* Check if vmlaunch of vmresume is needed */
		"cmpl $0, %c[launched](%0) \n\t"
		/* Load guest registers.  Don't clobber flags. */
		"mov %c[rax](%0), %%"R"ax \n\t"
		"mov %c[rbx](%0), %%"R"bx \n\t"
		"mov %c[rdx](%0), %%"R"dx \n\t"
		"mov %c[rsi](%0), %%"R"si \n\t"
		"mov %c[rdi](%0), %%"R"di \n\t"
		"mov %c[rbp](%0), %%"R"bp \n\t"
#ifdef CONFIG_X86_64
		"mov %c[r8](%0),  %%r8  \n\t"
		"mov %c[r9](%0),  %%r9  \n\t"
		"mov %c[r10](%0), %%r10 \n\t"
		"mov %c[r11](%0), %%r11 \n\t"
		"mov %c[r12](%0), %%r12 \n\t"
		"mov %c[r13](%0), %%r13 \n\t"
		"mov %c[r14](%0), %%r14 \n\t"
		"mov %c[r15](%0), %%r15 \n\t"
#endif
		"mov %c[rcx](%0), %%"R"cx \n\t" /* kills %0 (ecx) */

		/* Enter guest mode */
		"jne .Llaunched \n\t"
		ASM_VMX_VMLAUNCH "\n\t"
		"jmp .Lkvm_vmx_return \n\t"
		".Llaunched: " ASM_VMX_VMRESUME "\n\t"
		".Lkvm_vmx_return: "
		/* Save guest registers, load host registers, keep flags */
		"mov %0, %c[wordsize](%%"R"sp) \n\t"
		"pop %0 \n\t"
		"mov %%"R"ax, %c[rax](%0) \n\t"
		"mov %%"R"bx, %c[rbx](%0) \n\t"
		"pop"Q" %c[rcx](%0) \n\t"
		"mov %%"R"dx, %c[rdx](%0) \n\t"
		"mov %%"R"si, %c[rsi](%0) \n\t"
		"mov %%"R"di, %c[rdi](%0) \n\t"
		"mov %%"R"bp, %c[rbp](%0) \n\t"
#ifdef CONFIG_X86_64
		"mov %%r8,  %c[r8](%0) \n\t"
		"mov %%r9,  %c[r9](%0) \n\t"
		"mov %%r10, %c[r10](%0) \n\t"
		"mov %%r11, %c[r11](%0) \n\t"
		"mov %%r12, %c[r12](%0) \n\t"
		"mov %%r13, %c[r13](%0) \n\t"
		"mov %%r14, %c[r14](%0) \n\t"
		"mov %%r15, %c[r15](%0) \n\t"
#endif
		"mov %%rax, %%r10 \n\t"
		"mov %%rdx, %%r11 \n\t"

		"mov %%cr2, %%"R"ax   \n\t"
		"mov %%"R"ax, %c[cr2](%0) \n\t"

		"pop  %%"R"bp; pop  %%"R"dx \n\t"
		"setbe %c[fail](%0) \n\t"

		"mov $" __stringify(__USER_DS) ", %%rax \n\t"
		"mov %%rax, %%ds \n\t"
		"mov %%rax, %%es \n\t"
	      : : "c"(vcpu), "d"((unsigned long)HOST_RSP),
		[launched]"i"(offsetof(struct vmx_vcpu, launched)),
		[fail]"i"(offsetof(struct vmx_vcpu, fail)),
		[host_rsp]"i"(offsetof(struct vmx_vcpu, host_rsp)),
		[rax]"i"(offsetof(struct vmx_vcpu, regs[VCPU_REGS_RAX])),
		[rbx]"i"(offsetof(struct vmx_vcpu, regs[VCPU_REGS_RBX])),
		[rcx]"i"(offsetof(struct vmx_vcpu, regs[VCPU_REGS_RCX])),
		[rdx]"i"(offsetof(struct vmx_vcpu, regs[VCPU_REGS_RDX])),
		[rsi]"i"(offsetof(struct vmx_vcpu, regs[VCPU_REGS_RSI])),
		[rdi]"i"(offsetof(struct vmx_vcpu, regs[VCPU_REGS_RDI])),
		[rbp]"i"(offsetof(struct vmx_vcpu, regs[VCPU_REGS_RBP])),
#ifdef CONFIG_X86_64
		[r8]"i"(offsetof(struct vmx_vcpu, regs[VCPU_REGS_R8])),
		[r9]"i"(offsetof(struct vmx_vcpu, regs[VCPU_REGS_R9])),
		[r10]"i"(offsetof(struct vmx_vcpu, regs[VCPU_REGS_R10])),
		[r11]"i"(offsetof(struct vmx_vcpu, regs[VCPU_REGS_R11])),
		[r12]"i"(offsetof(struct vmx_vcpu, regs[VCPU_REGS_R12])),
		[r13]"i"(offsetof(struct vmx_vcpu, regs[VCPU_REGS_R13])),
		[r14]"i"(offsetof(struct vmx_vcpu, regs[VCPU_REGS_R14])),
		[r15]"i"(offsetof(struct vmx_vcpu, regs[VCPU_REGS_R15])),
#endif
		[cr2]"i"(offsetof(struct vmx_vcpu, cr2)),
		[wordsize]"i"(sizeof(ulong))
	      : "cc", "memory"
		, R"ax", R"bx", R"di", R"si"
#ifdef CONFIG_X86_64
		, "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
#endif
	);

	vcpu->launched = 1;

	if (unlikely(vcpu->fail)) {
		printk(KERN_ERR "vmx: failure detected (err %x)\n",
		       vmcs_read32(VM_INSTRUCTION_ERROR));
		return VMX_EXIT_REASONS_FAILED_VMENTRY;
	}

	return vmcs_read32(VM_EXIT_REASON);

#if 0
	vmx->idt_vectoring_info = vmcs_read32(IDT_VECTORING_INFO_FIELD);
	vmx_complete_atomic_exit(vmx);
	vmx_recover_nmi_blocking(vmx);
	vmx_complete_interrupts(vmx);
#endif
}

static void vmx_step_instruction(void)
{
	vmcs_writel(GUEST_RIP, vmcs_readl(GUEST_RIP) +
			       vmcs_read32(VM_EXIT_INSTRUCTION_LEN));
}

static int vmx_handle_ept_violation(struct vmx_vcpu *vcpu)
{
	unsigned long gva, gpa;
	int exit_qual, ret;

	vmx_get_cpu(vcpu);
	exit_qual = vmcs_read32(EXIT_QUALIFICATION);
	gva = vmcs_readl(GUEST_LINEAR_ADDRESS);
	gpa = vmcs_read64(GUEST_PHYSICAL_ADDRESS);
	vmx_put_cpu(vcpu);
	
	if (exit_qual & (1 << 6)) {
		printk(KERN_ERR "EPT: GPA 0x%lx exceeds GAW!\n", gpa);
		return -EINVAL;
	}
	
	if (!(exit_qual & (1 << 7))) {
		printk(KERN_ERR "EPT: linear address is not valid, GPA: 0x%lx!\n", gpa);
		return -EINVAL;
	}

	ret = vmx_do_ept_fault(vcpu, gpa, gva, exit_qual);

	if (ret) {
		printk(KERN_ERR "vmx: page fault failure "
		       "GPA: 0x%lx, GVA: 0x%lx\n",
		       gpa, gva);
		vcpu->ret_code = ((EFAULT) << 8);
		vmx_dump_cpu(vcpu);
	}

	return ret;
}

static void vmx_handle_syscall(struct vmx_vcpu *vcpu)
{
	if (unlikely(vcpu->regs[VCPU_REGS_RAX] > NUM_SYSCALLS)) {
		vcpu->regs[VCPU_REGS_RAX] = -EINVAL;
		return;
	}
	
	if (unlikely(vcpu->regs[VCPU_REGS_RAX] == __NR_sigaltstack ||
		     vcpu->regs[VCPU_REGS_RAX] == __NR_iopl)) {
		printk(KERN_INFO "vmx: got unsupported syscall\n");
		vcpu->regs[VCPU_REGS_RAX] = -EINVAL;
		return;
	}

	asm(
		"mov %c[rax](%0), %%"R"ax \n\t"
		"mov %c[rdi](%0), %%"R"di \n\t"
		"mov %c[rsi](%0), %%"R"si \n\t"
		"mov %c[rdx](%0), %%"R"dx \n\t"
		"mov %c[r8](%0),  %%r8  \n\t"
		"mov %c[r9](%0),  %%r9  \n\t"
		"mov %c[syscall](%0), %%r10 \n\t"
		"mov %0, %%r11 \n\t"
		"push %0 \n\t"
		"mov %c[r10](%0), %%"R"cx \n\t"
		"shl $3, %%rax \n\t"
		"add %%r10, %%rax\n\t"
		"call *(%%rax) \n\t"
		"pop %0 \n\t"
		"mov %%"R"ax, %c[rax](%0) \n\t"

		: : "c"(vcpu),
		[syscall]"i"(offsetof(struct vmx_vcpu, syscall_tbl)),
		[rax]"i"(offsetof(struct vmx_vcpu, regs[VCPU_REGS_RAX])),
		[rdi]"i"(offsetof(struct vmx_vcpu, regs[VCPU_REGS_RDI])),
		[rsi]"i"(offsetof(struct vmx_vcpu, regs[VCPU_REGS_RSI])),
		[rdx]"i"(offsetof(struct vmx_vcpu, regs[VCPU_REGS_RDX])),
		[r10]"i"(offsetof(struct vmx_vcpu, regs[VCPU_REGS_R10])),
		[r8]"i"(offsetof(struct vmx_vcpu, regs[VCPU_REGS_R8])),
		[r9]"i"(offsetof(struct vmx_vcpu, regs[VCPU_REGS_R9]))
	      : "cc", "memory", R"ax", R"dx", R"di", R"si", "r8", "r9", "r10"
	);
}

static void vmx_handle_cpuid(struct vmx_vcpu *vcpu)
{
	unsigned int eax, ebx, ecx, edx;

	eax = vcpu->regs[VCPU_REGS_RAX];
	ecx = vcpu->regs[VCPU_REGS_RCX];
	native_cpuid(&eax, &ebx, &ecx, &edx);
	vcpu->regs[VCPU_REGS_RAX] = eax;
	vcpu->regs[VCPU_REGS_RBX] = ebx;
	vcpu->regs[VCPU_REGS_RCX] = ecx;
	vcpu->regs[VCPU_REGS_RDX] = edx;
}

static int vmx_handle_nmi_exception(struct vmx_vcpu *vcpu)
{
	u32 intr_info;

	vmx_get_cpu(vcpu);
	intr_info = vmcs_read32(VM_EXIT_INTR_INFO);
	vmx_put_cpu(vcpu);

	printk(KERN_INFO "vmx: got an exception\n");
	if ((intr_info & INTR_INFO_INTR_TYPE_MASK) == INTR_TYPE_NMI_INTR)
		return 0;

	printk(KERN_ERR "vmx: unhandled nmi, intr_info %x\n", intr_info);
	vcpu->ret_code = ((EFAULT) << 8);
	return -EIO;
}

/**
 * vmx_launch - the main loop for a VMX Dune process
 * @conf: the launch configuration
 */
int vmx_launch(struct dune_config *conf, int64_t *ret_code)
{
	int ret, done = 0;
	struct vmx_vcpu *vcpu = vmx_create_vcpu(conf);
	if (!vcpu)
		return -ENOMEM;

	printk(KERN_ERR "vmx: created VCPU (VPID %d)\n",
	       vcpu->vpid);

	while (1) {
		vmx_get_cpu(vcpu);

		/*
		 * We assume that a Dune process will always use
		 * the FPU whenever it is entered, and thus we go
		 * ahead and load FPU state here. The reason is
		 * that we don't monitor or trap FPU usage inside
		 * a Dune process.
		 */
		if (!__thread_has_fpu(current))
			math_state_restore();

		local_irq_disable();

		if (need_resched()) {
			local_irq_enable();
			vmx_put_cpu(vcpu);
			cond_resched();
			continue;
		}

		if (signal_pending(current)) {
			int signr;
			siginfo_t info;
			uint32_t x;

			local_irq_enable();
			vmx_put_cpu(vcpu);

			spin_lock_irq(&current->sighand->siglock);
			signr = dequeue_signal(current, &current->blocked,
					       &info);
			spin_unlock_irq(&current->sighand->siglock);
			if (!signr)
				continue;

			if (signr == SIGKILL) {
				printk(KERN_INFO "vmx: got sigkill, dying");
				vcpu->ret_code = ((ENOSYS) << 8);
				break;
			}

			x  = DUNE_SIGNAL_INTR_BASE + signr;
			x |= INTR_INFO_VALID_MASK;

			vmcs_write32(VM_ENTRY_INTR_INFO_FIELD, x);
			continue;
		}

		ret = vmx_run_vcpu(vcpu);

		local_irq_enable();

		if (ret == EXIT_REASON_VMCALL ||
		    ret == EXIT_REASON_CPUID) {
			vmx_step_instruction();
		}

		vmx_put_cpu(vcpu);

		if (ret == EXIT_REASON_VMCALL)
			vmx_handle_syscall(vcpu);
		else if (ret == EXIT_REASON_CPUID)
			vmx_handle_cpuid(vcpu);
		else if (ret == EXIT_REASON_EPT_VIOLATION)
			done = vmx_handle_ept_violation(vcpu);
		else if (ret == EXIT_REASON_EXCEPTION_NMI) {
			if (vmx_handle_nmi_exception(vcpu))
				done = 1;
		} else if (ret != EXIT_REASON_EXTERNAL_INTERRUPT) {
			printk(KERN_INFO "unhandled exit: reason %d, exit qualification %x\n",
			       ret, vmcs_read32(EXIT_QUALIFICATION));
			vmx_dump_cpu(vcpu);
			done = 1;
		}

		if (done || vcpu->shutdown)
			break;
	}

	printk(KERN_ERR "vmx: destroying VCPU (VPID %d)\n",
	       vcpu->vpid);

	*ret_code = vcpu->ret_code;
	vmx_destroy_vcpu(vcpu);

	return 0;
}

/**
 * __vmx_enable - low-level enable of VMX mode on the current CPU
 * @vmxon_buf: an opaque buffer for use as the VMXON region
 */
static __init int __vmx_enable(struct vmcs *vmxon_buf)
{
	u64 phys_addr = __pa(vmxon_buf);
	u64 old, test_bits;

	if (read_cr4() & X86_CR4_VMXE)
		return -EBUSY;

	rdmsrl(MSR_IA32_FEATURE_CONTROL, old);

	test_bits = FEATURE_CONTROL_LOCKED;
	test_bits |= FEATURE_CONTROL_VMXON_ENABLED_OUTSIDE_SMX;
	if (tboot_enabled())
		test_bits |= FEATURE_CONTROL_VMXON_ENABLED_INSIDE_SMX;

	if ((old & test_bits) != test_bits) {
		/* enable and lock */
		wrmsrl(MSR_IA32_FEATURE_CONTROL, old | test_bits);
	}
	write_cr4(read_cr4() | X86_CR4_VMXE);

	__vmxon(phys_addr);
	vpid_sync_vcpu_global();
	ept_sync_global();

	return 0;
}

/**
 * vmx_enable - enables VMX mode on the current CPU
 * @unused: not used (required for on_each_cpu())
 *
 * Sets up necessary state for enable (e.g. a scratchpad for VMXON.)
 */
static __init void vmx_enable(void *unused)
{
	int ret;
	struct vmcs *vmxon_buf = __get_cpu_var(vmxarea);

	if ((ret = __vmx_enable(vmxon_buf)))
		goto failed;

	__get_cpu_var(vmx_enabled) = 1;
	native_store_gdt(&__get_cpu_var(host_gdt));

	printk(KERN_INFO "vmx: VMX enabled on CPU %d\n",
	       raw_smp_processor_id());
	return;

failed:
	atomic_inc(&vmx_enable_failed);
	printk(KERN_ERR "vmx: failed to enable VMX, err = %d\n", ret);
}

/**
 * vmx_disable - disables VMX mode on the current CPU
 */
static void vmx_disable(void *unused)
{
	if (__get_cpu_var(vmx_enabled)) {
		__vmxoff();
		write_cr4(read_cr4() & ~X86_CR4_VMXE);
		__get_cpu_var(vmx_enabled) = 0;
	}
}

/**
 * vmx_free_vmxon_areas - cleanup helper function to free all VMXON buffers
 */
static void vmx_free_vmxon_areas(void)
{
	int cpu;

	for_each_possible_cpu(cpu) {
		if (per_cpu(vmxarea, cpu)) {
			vmx_free_vmcs(per_cpu(vmxarea, cpu));
			per_cpu(vmxarea, cpu) = NULL;
		}
	}
}

/**
 * vmx_init - the main initialization routine for this driver
 */
__init int vmx_init(void)
{
	int r, cpu;
	
	if (!cpu_has_vmx()) {
		printk(KERN_ERR "vmx: CPU does not support VT-x\n");
		return -EIO;
	}

	vmx_init_syscall();

	if (setup_vmcs_config(&vmcs_config) < 0)
		return -EIO;

	if (!cpu_has_vmx_vpid()) {
		printk(KERN_ERR "vmx: CPU is missing required feature 'VPID'\n");
		return -EIO;
	}

	if (!cpu_has_vmx_ept()) {
		printk(KERN_ERR "vmx: CPU is missing required feature 'EPT'\n");
		return -EIO;
	}

	if (!vmx_capability.has_load_efer) {
		printk(KERN_ERR "vmx: ability to load EFER register is required\n");
		return -EIO;
	}

	msr_bitmap = (unsigned long *)__get_free_page(GFP_KERNEL);
	if (!msr_bitmap) {
		return -ENOMEM;
	}
	/* FIXME: do we need APIC virtualization (flexpriority?) */

	memset(msr_bitmap, 0xff, PAGE_SIZE);
	__vmx_disable_intercept_for_msr(msr_bitmap, MSR_FS_BASE);
	__vmx_disable_intercept_for_msr(msr_bitmap, MSR_GS_BASE);

	set_bit(0, vmx_vpid_bitmap); /* 0 is reserved for host */

	for_each_possible_cpu(cpu) {
		struct vmcs *vmxon_buf;

		vmxon_buf = __vmx_alloc_vmcs(cpu);
		if (!vmxon_buf) {
			vmx_free_vmxon_areas();
			return -ENOMEM;
		}

		per_cpu(vmxarea, cpu) = vmxon_buf;
	}

	atomic_set(&vmx_enable_failed, 0);
	if (on_each_cpu(vmx_enable, NULL, 1)) {
		printk(KERN_ERR "vmx: timeout waiting for VMX mode enable.\n");
		r = -EIO;
		goto failed1; /* sadly we can't totally recover */
	}

	if (atomic_read(&vmx_enable_failed)) {
		r = -EBUSY;
		goto failed2;
	}

	return 0;

failed2:
	on_each_cpu(vmx_disable, NULL, 1);
failed1:
	vmx_free_vmxon_areas();
	return r;
}

/**
 * vmx_exit - the main removal routine for this driver
 */
void vmx_exit(void)
{
	on_each_cpu(vmx_disable, NULL, 1);
	vmx_free_vmxon_areas();
	free_page((unsigned long)msr_bitmap);
}
