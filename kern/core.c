/**
 * core.c - the Dune core
 *
 * Dune allows ordinary Linux processes to access the full collection of x86
 * hardware protection and isolation mechanisms (e.g. paging, segmentation)
 * through hardware virtualization. Unlike traditional virtual machines,
 * Dune processes can make ordinary POSIX system calls and, with the exception
 * of access to privileged hardware features, are treated like normal Linux
 * processes.
 *
 * FIXME: Currently only Intel VMX is supported.
 *
 * Authors:
 *   Adam Belay   <abelay@stanford.edu>
 */

#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/miscdevice.h>
#include <linux/compat.h>
#include <linux/fs.h>
#include <linux/perf_event.h>
#include <asm/uaccess.h>

#include "dune.h"
#include "vmx.h"

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("A driver for Dune");

/* Callbacks for perf tool.  We intentionally make a wrong assumption that we
 * are always in the kernel mode because perf cannot profile user applications
 * on guest.
 * Callbacks are registered and unregistered along with Dune module.
 */
static int dune_is_in_guest(void)
{
	return __get_cpu_var(local_vcpu) != NULL;
}

static int dune_is_user_mode(void)
{
        return 0;
}

static unsigned long dune_get_guest_ip(void)
{
	unsigned long long ip = 0;
	if (__get_cpu_var(local_vcpu))
		ip = vmcs_readl(GUEST_RIP);
	return ip;
}

static struct perf_guest_info_callbacks dune_guest_cbs = {
        .is_in_guest            = dune_is_in_guest,
        .is_user_mode           = dune_is_user_mode,
        .get_guest_ip           = dune_get_guest_ip,
};

static int dune_enter(struct dune_config *conf, int64_t *ret)
{
	return vmx_launch(conf, ret);
}

static long dune_dev_ioctl(struct file *filp,
			  unsigned int ioctl, unsigned long arg)
{
	long r = -EINVAL;
	struct dune_config conf;
	struct dune_layout layout;

	switch (ioctl) {
	case DUNE_ENTER:
		r = copy_from_user(&conf, (int __user *) arg,
				   sizeof(struct dune_config));
		if (r) {
			r = -EIO;
			goto out;
		}

		r = dune_enter(&conf, &conf.ret);
		if (r)
			break;

		r = copy_to_user((void __user *)arg, &conf,
				 sizeof(struct dune_config));
		if (r) {
			r = -EIO;
			goto out;
		}
		break;

	case DUNE_GET_SYSCALL:
		rdmsrl(MSR_LSTAR, r);
		printk(KERN_INFO "R %lx\n", (unsigned long) r);
		break;

	case DUNE_GET_LAYOUT:
		layout.phys_limit = (1UL << boot_cpu_data.x86_phys_bits);
		layout.base_map = LG_ALIGN(current->mm->mmap_base) - GPA_MAP_SIZE;
		layout.base_stack = LG_ALIGN(current->mm->start_stack) - GPA_STACK_SIZE;
		r = copy_to_user((void __user *)arg, &layout,
				 sizeof(struct dune_layout));
		if (r) {
			r = -EIO;
			goto out;
		}
		break;

	default:
		return -ENOTTY;
	}

out:
	return r;
}

static const struct file_operations dune_chardev_ops = {
	.owner		= THIS_MODULE,
	.unlocked_ioctl	= dune_dev_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= dune_dev_ioctl,
#endif
	.llseek		= noop_llseek,
};

static struct miscdevice dune_dev = {
	DUNE_MINOR,
	"dune",
	&dune_chardev_ops,
};

static int __init dune_init(void)
{
	int r;
	perf_register_guest_info_callbacks(&dune_guest_cbs);

	printk(KERN_ERR "Dune module loaded\n");

	if ((r = vmx_init())) {
		printk(KERN_ERR "dune: failed to initialize vmx\n");
		return r;
	}

	r = misc_register(&dune_dev);
	if (r) {
		printk(KERN_ERR "dune: misc device register failed\n");
		vmx_exit();
	}

	return r;
}

static void __exit dune_exit(void)
{
	perf_unregister_guest_info_callbacks(&dune_guest_cbs);
	misc_deregister(&dune_dev);
	vmx_exit();
}

module_init(dune_init);
module_exit(dune_exit);
