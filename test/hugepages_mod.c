#include <asm/uaccess.h>
#include <asm/vmx.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/uaccess.h>

#include "hugepages.h"

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("hugepages_mod");

static unsigned long vmcs_read64(unsigned long field)
{
	unsigned long value;
	asm volatile (ASM_VMX_VMREAD_RDX_RAX : "=a"(value) : "d"(field) : "cc");
	return value;
}

static long hugepages_ioctl(struct file *filp, unsigned int ioctl, unsigned long arg)
{
	long r = -EINVAL;
	unsigned long cr3, addr, data, eptp;

	switch (ioctl) {
	case HUGEPAGES_GET_CR3:
		cr3 = get_cr3();
		r = copy_to_user((void __user *)arg, &cr3, sizeof(cr3));
		if (r) {
			r = -EIO;
			goto out;
		}
		break;

	case HUGEPAGES_GET_EPTP:
		eptp = vmcs_read64(EPT_POINTER) & PAGE_MASK;
		r = copy_to_user((void __user *)arg, &eptp, sizeof(eptp));
		if (r) {
			r = -EIO;
			goto out;
		}
		break;

	case HUGEPAGES_READ_MEM:
		r = copy_from_user(&addr, (void __user *)arg, sizeof(addr));
		if (r) {
			r = -EIO;
			goto out;
		}
		data = *((unsigned long *)__va(addr));
		r = copy_to_user((void __user *)arg, &data, sizeof(data));
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

static const struct file_operations chardev_ops = {
	.owner		= THIS_MODULE,
	.unlocked_ioctl	= hugepages_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= hugepages_ioctl,
#endif
	.llseek		= noop_llseek,
};

static struct miscdevice dev = {
	MISC_DYNAMIC_MINOR,
	"hugepages_mod",
	&chardev_ops,
	.mode = S_IRUGO | S_IWUGO,
};

static int __init mod_init(void)
{
	return misc_register(&dev);
}

static void __exit mod_exit(void)
{
	misc_deregister(&dev);
}

module_init(mod_init);
module_exit(mod_exit);
