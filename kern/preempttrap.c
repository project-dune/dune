#include <linux/uaccess.h>
#include <linux/user-return-notifier.h>

#include "dune.h"

static struct dune_trap_config trap_conf;

static struct {
	__u8 enabled;
	__u8 triggered;
	__u8 count;
} trap_state;

static void notifier_sched_in(struct preempt_notifier *notifier, int cpu)
{
	if (!trap_state.triggered &&
	    KSTK_EIP(current) == trap_conf.trigger_rip) {
		trap_state.triggered = 1;
		trap_state.count = trap_conf.delay;
	}

	if (trap_state.triggered && trap_state.count-- == 0) {
		struct pt_regs *regs = task_pt_regs(current);
		struct dune_trap_regs trap_regs;

		trap_state.triggered = 0;

		trap_regs.rax = regs->ax;
		trap_regs.rbx = regs->bx;
		trap_regs.rcx = regs->cx;
		trap_regs.rdx = regs->dx;
		trap_regs.rsi = regs->si;
		trap_regs.rdi = regs->di;
		trap_regs.rsp = regs->sp;
		trap_regs.rbp = regs->bp;
		trap_regs.r8 = regs->r8;
		trap_regs.r9 = regs->r9;
		trap_regs.r10 = regs->r10;
		trap_regs.r11 = regs->r11;
		trap_regs.r12 = regs->r12;
		trap_regs.r13 = regs->r13;
		trap_regs.r14 = regs->r14;
		trap_regs.r15 = regs->r15;
		trap_regs.rip = regs->ip;
		trap_regs.rflags = regs->flags;

		/* Debuggers use the single step flags to get notification when
		 * a breakpointed instruction is executed, so that they can
		 * restore the int3 opcode. Unset the flags so that they don't
		 * get the notification in our notify_func.
		 */
		regs->flags &= ~X86_EFLAGS_TF;
		clear_thread_flag(TIF_SINGLESTEP);

		if (sizeof(struct dune_trap_regs) == trap_conf.regs_size) {
			copy_to_user((void __user *)trap_conf.regs,
				     &trap_regs, sizeof(struct dune_trap_regs));
			regs->ip = (__u64)trap_conf.notify_func;
			regs->di = (__u64)trap_conf.regs;
			regs->si = (__u64)trap_conf.priv;
			/* Go past the red zone mandated by the System V
			 * x86-64 ABI.
			 */
			regs->sp -= 128;
		}
	}
}

static void notifier_sched_out(struct preempt_notifier *notifier,
			       struct task_struct *next)
{
}

static struct preempt_ops notifier_ops = {
	.sched_in = notifier_sched_in,
	.sched_out = notifier_sched_out,
};

static struct preempt_notifier notifier = {
	.ops = &notifier_ops,
};

long dune_trap_enable(unsigned long arg)
{
	unsigned long r;

	r = copy_from_user(&trap_conf, (void __user *)arg,
			   sizeof(struct dune_trap_config));
	if (r) {
		r = -EIO;
		goto out;
	}

	preempt_notifier_register(&notifier);
	trap_state.enabled = 1;

out:
	return r;
}

long dune_trap_disable(unsigned long arg)
{
	if (trap_state.enabled)
		preempt_notifier_unregister(&notifier);
	trap_state.enabled = 0;

	return 0;
}
