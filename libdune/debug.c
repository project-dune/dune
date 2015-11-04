#include <signal.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "debug.h"
#include "local.h"

#define X86_EFLAGS_TF (0x100)

static struct dune_trap_regs trap_regs;

extern int dune_fd;

static void dune_trap_enable(__u64 trigger_rip, __u8 delay, dune_trap_notify_func func, void *priv)
{
	struct dune_trap_config trap_conf = {
		.trigger_rip = (__u64) trigger_rip,
		.delay = delay,
		.notify_func = func,
		.regs = &trap_regs,
		.regs_size = sizeof(trap_regs),
		.priv = priv,
	};

	ioctl(dune_fd, DUNE_TRAP_ENABLE, &trap_conf);
}

static void dune_trap_disable()
{
	ioctl(dune_fd, DUNE_TRAP_DISABLE);
}

static void notify_on_resume(struct dune_trap_regs *regs, void *priv)
{
	struct dune_config *dune_conf = (struct dune_config *) priv;

	/* We don't need the preemption trap anymore. */
	dune_trap_disable();

	/* Copy the TF bit from Linux mode to Dune mode. This way, the program
	 * will either single-step or continue depending on what the debugger
	 * wants the program to do. */
	dune_conf->rflags &= ~X86_EFLAGS_TF;
	dune_conf->rflags |= regs->rflags & X86_EFLAGS_TF;

	/* Continue in Dune mode. */
	__dune_go_dune(dune_fd, dune_conf);
	/* It doesn't return. */
}

void dune_debug_handle_int(struct dune_config *conf)
{
	switch (conf->status) {
	case 1: /* single step */
		/* Setup notification when Linux wants to execute the
		 * instruction. By then Linux will have already delivered the
		 * SIGTRAP signal to the debugger and we will be able to switch
		 * back to Dune mode. */
		dune_trap_enable(conf->rip, 0, notify_on_resume, conf);

		/* Set TF flag so that Linux will raise the SIGTRAP signal. */
		conf->rflags |= X86_EFLAGS_TF;

		/* Continue in Linux mode. Actually, this will only deliver the
		 * signal. Due to the trap setup above no instructions are going
		 * to be executed in Linux mode. */
		__dune_go_linux(conf);
		/* It doesn't return. */
		break;
	case 3: /* breakpoint */
		/* Setup notification when Linux tries to execute the
		 * breakpointed instruction. */
		dune_trap_enable(conf->rip, 0, notify_on_resume, conf);

		/* Continue in Linux mode. This will hit the int3 again for the
		 * debugger to catch it. */
		__dune_go_linux(conf);
		/* It doesn't return. */
		break;
	default:
		break;
	}
}
