/*
 * dune.S - assembly helper routines (e.g. system calls, interrupts, traps)
 */

#define __ASSEMBLY__
#include "../kern/dune.h"

#define USE_RDWRGSFS 0

#define MSR_FS_BASE	0xc0000100
#define GD_KT		0x10
#define GD_KD		0x18
#define GD_UD		0x28 | 0x03
#define GD_UT		0x30 | 0x03

/*
 * Trap Frame Format
 * NOTE: this reflects the layout of struct dune_tf
 */

/* arguments */
#define RDI	(0)
#define RSI	(8)
#define RDX	(16)
#define RCX	(24)
#define R8	(32)
#define R9	(40)

/* other registers */
#define R10	(48)
#define R11	(56)
#define RBX	(64)
#define RBP	(72)
#define R12	(80)
#define R13	(88)
#define R14	(96)
#define R15	(104)

#define REG_END	(112)

/* syscall num / return code */
#define RAX	(112)

/* exception frame */
#define ERR	(120)
#define RIP	(128)
#define CS	(136)
#define RFLAGS	(144)
#define RSP	(152)
#define SS	(160)

#define EF_START (128)
#define TF_END	(168)
#define TF_ALIGN (176)

/*
 * Supervisor Private Area Format
 */

#define TMP		(8)
#define KFS_BASE	(16)
#define UFS_BASE	(24)
#define IN_USERMODE	(32)
#define TRAP_STACK	(44)

.text

/*
 * macro to save destructable register state
 */
	.macro SAVE_REGS save_full=1, include_rax=1
	movq	%rdi, RDI(%rsp)
	movq	%rsi, RSI(%rsp)
	movq	%rdx, RDX(%rsp)
	movq	%r8, R8(%rsp)
	movq	%r9, R9(%rsp)

	.if \save_full
	movq	%r10, R10(%rsp)
	movq	%r11, R11(%rsp)
	movq	%rcx, RCX(%rsp)
	.endif

	.if \include_rax
	movq	%rax, RAX(%rsp)
	.endif
	.endm

/*
 * macro to save the rest of register state
 *
 * useful for operations that violate AMD64 calling conventions
 * by destroying callee restored state
 */
	.macro SAVE_REST
	movq	%rbx, RBX(%rsp)
	movq	%rbp, RBP(%rsp)
	movq	%r12, R12(%rsp)
	movq	%r13, R13(%rsp)
	movq	%r14, R14(%rsp)
	movq	%r15, R15(%rsp)
	.endm

/*
 * macro to restore destructable register state
 */
	.macro RESTORE_REGS rstor_full=1, include_rax=1
	.if \include_rax
	movq	RAX(%rsp), %rax
	.endif

	.if \rstor_full
	movq	RCX(%rsp), %rcx
	movq	R11(%rsp), %r11
	movq	R10(%rsp), %r10
	.endif

	movq	R9(%rsp), %r9
	movq	R8(%rsp), %r8
	movq	RDX(%rsp), %rdx
	movq	RSI(%rsp), %rsi
	movq	RDI(%rsp), %rdi
	.endm

/*
 * macro to restore the rest of register state
 *
 * useful for operations that violate AMD64 calling conventions
 * by destroying callee restored state
 */
	.macro RESTORE_REST
	movq	R15(%rsp), %r15
	movq	R14(%rsp), %r14
	movq	R13(%rsp), %r13
	movq	R12(%rsp), %r12
	movq	RBP(%rsp), %rbp
	movq	RBX(%rsp), %rbx
	.endm

/*
 * macro to switch to G0 fs.base
 *
 * NOTE: clobbers %rax, %rdx, and %rcx
 */
	.macro SET_G0_FS_BASE
	movq	$0, %gs:IN_USERMODE
	movq	%gs:KFS_BASE, %rax
	movq	%gs:UFS_BASE, %rdx
	cmp	%rax, %rdx
	je	1f
#if USE_RDWRGSFS
	wrfsbase %rax
#else
	movq	%rax, %rdx
	shrq	$32, %rdx
	movl	$MSR_FS_BASE, %ecx
	wrmsr
#endif /* USE_RDWRGSFS */
1:
	.endm

/*
 * macro to switch to G3 fs.base
 *
 * NOTE: clobbers %rax, %rdx, and %rcx
 */
	.macro SET_G3_FS_BASE
	movq	$1, %gs:IN_USERMODE
	movq	%gs:UFS_BASE, %rax
	movq	%gs:KFS_BASE, %rdx
	cmp	%rax, %rdx
	je	1f
#if USE_RDWRGSFS
	wrfsbase %rax
#else
	movq	%rax, %rdx
	shrq	$32, %rdx
	movl	$MSR_FS_BASE, %ecx
	wrmsr
#endif /* USE_RDWRGSFS */
1:
	.endm

.globl __dune_enter
__dune_enter:
	pushfq
	subq	$REG_END, %rsp
	SAVE_REGS 1, 0
	SAVE_REST
	movq	%rsp, DUNE_CFG_RSP(%rsi)
	movq	%rsi, %rdx
	movq	$IOCTL_DUNE_ENTER, %rsi
	movq	$16, %rax /* __NR_ioctl */
	syscall

	cmpq	$0, %rax
	jnz __dune_ret_fail

	movq	%rdi, %r12
	movq	%rdx, %r13

__dune_retry:
	/* Dune mode was terminated, call on_dune_exit handler function */
	movq	%r13, %rdi
	/* Update RSP to point to the top of the stack as seen from inside Dune
	 * mode. */
	movq	DUNE_CFG_RSP(%rdi), %rsp
	/* Go past the red zone mandated by the System V x86-64 ABI. */
	subq	$128, %rsp
	call	on_dune_exit
	int3 /* sentinel: on_dune_exit should not return */
__dune_reenter:
	movq	%r12, %rdi
	movq	%r13, %rdx
	movq	$IOCTL_DUNE_ENTER, %rsi
	movq	$16, %rax /* __NR_ioctl */
	syscall
	cmpq	$0, %rax
	jz	__dune_retry
	movq	%rax, DUNE_CFG_STATUS(%r13)
	movq	$DUNE_RET_NOENTER, DUNE_CFG_RET(%r13)
	jmp	__dune_retry

/* __dune_ret is the location of the first instruction executed in Dune mode */
.globl	__dune_ret
__dune_ret:
	xorq %rax, %rax /* return 0 from __dune_enter */

__dune_ret_fail:
	RESTORE_REST
	RESTORE_REGS 1, 0
	addq	$REG_END, %rsp
	popfq
	retq

.globl __dune_go_linux
__dune_go_linux:
	movq DUNE_CFG_RCX(%rdi), %rcx
	movq DUNE_CFG_RBX(%rdi), %rbx
	movq DUNE_CFG_RDX(%rdi), %rdx
	movq DUNE_CFG_RBP(%rdi), %rbp
	movq DUNE_CFG_RSI(%rdi), %rsi
	movq DUNE_CFG_R8 (%rdi), %r8
	movq DUNE_CFG_R9 (%rdi), %r9
	movq DUNE_CFG_R10(%rdi), %r10
	movq DUNE_CFG_R11(%rdi), %r11
	movq DUNE_CFG_R12(%rdi), %r12
	movq DUNE_CFG_R13(%rdi), %r13
	movq DUNE_CFG_R14(%rdi), %r14
	movq DUNE_CFG_R15(%rdi), %r15
	mov %ss, %rax
	push %rax
	pushq DUNE_CFG_RSP(%rdi)
	pushq DUNE_CFG_RFLAGS(%rdi)
	mov %cs, %rax
	push %rax
	pushq DUNE_CFG_RIP(%rdi)
	pushq DUNE_CFG_RFLAGS(%rdi)
	movq DUNE_CFG_RAX(%rdi), %rax
	movq DUNE_CFG_RDI(%rdi), %rdi
	/* We are restoring the flags here, so that RFLAGS.TF is set when IRETQ is
	 * executed, so that an INT 1 will be raised _before_ executing the
	 * instruction at CS:RIP we are jumping to. */
	popf
	iretq

.globl __dune_go_dune
__dune_go_dune:
	movq	%rdi, %r12
	movq	%rsi, %r13
	jmp	__dune_reenter

/*
 * System Call ABI
 * ---------------
 *
 * User Parameters:
 * %rsp - stack pointer
 * %rcx - instruction pointer
 * %r11 - eflags
 * %rax - system call number
 *
 * Arguments:
 * %rdi - arg0, %rsi - arg1, %rdx - arg2
 * %r10 - arg3, %r8 - arg4, %r9 - arg5
 *
 * Return code goes in %rax
 *
 * XXX: don't do relative jumps - watch out code is memcpy
 */
.globl __dune_syscall
__dune_syscall:
	/* handle system calls from G0 */
	testq $1, %gs:IN_USERMODE
	jnz 1f
	pushq	%r11
	popfq
	vmcall
	jmp	*%rcx

1:
	/* first switch to the kernel stack */
	movq	%rsp, %gs:TMP
	movq	%gs:TRAP_STACK, %rsp

	/* now push the trap frame onto the stack */
	subq	$TF_END, %rsp
	movq	%rcx, RIP(%rsp)
	movq	%r11, RFLAGS(%rsp)
	movq	%r10, RCX(%rsp) /* fixup to standard 64-bit calling ABI */
	SAVE_REGS 0, 1
	movq	%gs:TMP, %rax
	movq	%rax, RSP(%rsp)

	/* then restore the CPL0 FS base address */
	SET_G0_FS_BASE

	/* then finally re-enable interrupts and jump to the handler */
	sti
	movq	%rsp, %rdi /* argument 0 */
	lea	dune_syscall_handler, %rax
	call	*%rax

	/* next restore the CPL3 FS base address */
	SET_G3_FS_BASE

	/* then pop the trap frame off the stack */
	RESTORE_REGS 0, 1
	movq	RCX(%rsp), %r10
	movq	RFLAGS(%rsp), %r11
	movq	RIP(%rsp), %rcx

	/* switch to the user stack and return to ring 3 */
	movq	RSP(%rsp), %rsp
	sysretq

.globl __dune_syscall_end
__dune_syscall_end:
	nop

.globl dune_pop_trap_frame
dune_pop_trap_frame:
	movq	%rdi, %rsp /* might actually not be a stack!!! */

	/* load the full register state */
	RESTORE_REGS
	RESTORE_REST

	/* jump to the frame */
	addq	$EF_START, %rsp
	iretq

.globl dune_jump_to_user
dune_jump_to_user:
	subq	$TF_ALIGN, %rsp

	/* save the full register state */
	SAVE_REGS
	SAVE_REST
	pushfq
	popq	RFLAGS(%rsp)

	/* save the stack pointer */
	movq	%rsp, %gs:TRAP_STACK

	/* set the CPL 3 FS.base */
	SET_G3_FS_BASE

	/* jump into G3 */
	movq	$GD_UT, CS(%rdi)
	movq	$GD_UD, SS(%rdi)
	jmp	dune_pop_trap_frame

.globl dune_ret_from_user
dune_ret_from_user:
	/* restore the G0 stack */
	movq	%rdi, %rsi
	movq	%gs:TRAP_STACK, %rdi

	/* return code */
	movq	%rsi, RAX(%rdi)

	/* fill in remaining exception frame data */
	lea	dune_ret_from_user_finish, %rax
	movq	%rax, RIP(%rdi)
	movq	$GD_KT, CS(%rdi)
	movq	$GD_KD, SS(%rdi)
	movq	%rdi, RSP(%rdi)

	/* return to the caller */
	jmp	dune_pop_trap_frame

dune_ret_from_user_finish:
	addq	$TF_ALIGN, %rsp
	ret

.globl __dune_intr
.align 16
__dune_intr:
	i = 0
	.rept 256
	.align 16
	.if i <> 8 && (i <= 9 || i >= 15) && i <> 17
		pushq	%rax /* placeholder for no error code */
	.endif
	pushq	%rax /* save %rax */
	mov $i, %rax
	jmp __dune_intr_with_num
	i = i + 1
	.endr

__dune_intr_with_num:
	/* save all registers */
	subq	$REG_END, %rsp
	SAVE_REGS 1, 0 /* %rax already is pushed */
	SAVE_REST
	movq	%rax, %rdi

	/* then restore the CPL0 FS base address */
	testq	$3, CS(%rsp)
	jz	__dune_intr_handler
	SET_G0_FS_BASE

__dune_intr_handler:
	/* setup arguments and call the handler */
	movq	%rsp, %rsi
	call	dune_trap_handler

	/* next restore the CPL3 FS base address */
	testq	$3, CS(%rsp)
	jz	__dune_intr_done
	SET_G3_FS_BASE

__dune_intr_done:
	/* load all registers */
	RESTORE_REST
	RESTORE_REGS

	/* jump to the frame */
	addq	$EF_START, %rsp
	iretq
