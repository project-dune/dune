/*
 * trap.c - handles system calls, page faults, and other traps
 */

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/syscall.h>
#include <asm/prctl.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <utime.h>

#include "sandbox.h"
#include "boxer.h"

static boxer_syscall_cb _syscall_monitor;

static void
pgflt_handler(uintptr_t addr, uint64_t fec, struct dune_tf *tf)
{
	int ret;
	ptent_t *pte;
	bool was_user = (tf->cs & 0x3);

	if (was_user) {
		printf("sandbox: got unexpected G3 page fault at addr %lx, fec %lx\n",
		       addr, fec);
		dune_dump_trap_frame(tf);
		dune_ret_from_user(-EFAULT);
	} else {
		ret = dune_vm_lookup(pgroot, (void *) addr, CREATE_NORMAL, &pte);
		assert(!ret);
		*pte = PTE_P | PTE_W | PTE_ADDR(dune_va_to_pa((void *) addr));
	}
}

static int check_extent(const void *ptr, size_t len)
{
	if (!mem_ref_is_safe(ptr, len)) {
		printf("sandbox: mem ref with addr %p, len %lx is out of range\n",
		       ptr, len);
		return -EFAULT;
	}

	return 0;
}

static int check_string(const void *ptr)
{
	void *pos;
	size_t maxlen;

	if ((uintptr_t) ptr < APP_MAX_ELF_VADDR)
		maxlen = APP_MAX_ELF_VADDR - ((uintptr_t) ptr);
	else if ((uintptr_t) ptr >= mmap_base) {
		if ((uintptr_t) ptr >= mmap_base + APP_MMAP_LEN)
			goto fault;
		maxlen = mmap_base + APP_MMAP_LEN - ((uintptr_t) ptr);
	} else
		goto fault;

	pos = memchr(ptr, 0, maxlen);
	if (!pos)
		goto fault;

	return 0;

fault:
	printf("str ref addr %p is out of range\n", ptr);
	return -EFAULT;
}

static inline long get_err(long ret)
{
	if (ret < 0)
		return -errno;
	else
		return ret;
}

void boxer_register_syscall_monitor(boxer_syscall_cb cb)
{
	_syscall_monitor = cb;
}

static int syscall_check_params(struct dune_tf *tf)
{
	void *ptr = NULL;
	uint64_t len = 0;
	char *str = NULL;
	int err = 0;

	switch (tf->rax) {
	case SYS_uname:
		ptr = (void*) ARG0(tf);
		len = sizeof(struct utsname);
		break;

	case SYS_arch_prctl:
		if (ARG0(tf) == ARCH_GET_FS) {
			ptr = (void*) ARG1(tf);
			len = sizeof(unsigned long);
		}
		break;

	case SYS_open:
	case SYS_unlink:
		str = (char*) ARG0(tf);
		break;

	case SYS_read:
	case SYS_write:
		ptr = (void*) ARG1(tf);
		len = ARG2(tf);
		break;

	case SYS_stat:
	case SYS_lstat:
		str = (char*) ARG0(tf);
	case SYS_fstat:
		ptr = (void*) ARG1(tf);
		len = sizeof(struct stat);
		break;

	/* XXX - doesn't belong here */
	case SYS_close:
		if (ARG0(tf) < 3) {
			tf->rax = 0;
			return -1;
		}
		break;

	/* XXX */
	case SYS_fcntl:
		if (ARG1(tf) != F_GETFL)
			err = -EINVAL;
		break;
	}

	if (ptr != NULL && len != 0 && check_extent(ptr, len))
		err = -EFAULT;

	if (str != NULL && check_string(str))
		err = -EFAULT;

	if (err) {
		tf->rax = err;
		return -1;
	}

	return 0;
}

static int syscall_allow(struct dune_tf *tf)
{
	if (!_syscall_monitor) {
		tf->rax = -EPERM;
		return 0;
	}

	return _syscall_monitor(tf);
}

static void syscall_do(struct dune_tf *tf)
{
	switch (tf->rax) {
	case SYS_arch_prctl:
		switch (ARG0(tf)) {
		case ARCH_GET_FS:
			*((unsigned long*) ARG1(tf)) = dune_get_user_fs();
			tf->rax = 0;
			break;

		case ARCH_SET_FS:
			dune_set_user_fs(ARG1(tf));
			tf->rax = 0;
			break;

		default:
			tf->rax = -EINVAL;
			break;
		}
		break;

	case SYS_brk:
		tf->rax = umm_brk((unsigned long) ARG0(tf));
		break;

	case SYS_mmap:
		tf->rax = (unsigned long) umm_mmap((void *) ARG0(tf),
			(size_t) ARG1(tf), (int) ARG2(tf), (int) ARG3(tf),
			(int) ARG4(tf), (off_t) ARG5(tf));
		break;

	case SYS_mprotect:
		tf->rax = umm_mprotect((void *) ARG0(tf),
				       (size_t) ARG1(tf),
				       ARG2(tf));
		break;

	case SYS_munmap:
		tf->rax = umm_munmap((void *) ARG0(tf), (size_t) ARG1(tf)); 
		break;

	case SYS_exit_group:
	case SYS_exit:
		dune_ret_from_user(ARG0(tf));
		break;

	default:
		dune_passthrough_syscall(tf);
		break;
	}
}

static void syscall_handler(struct dune_tf *tf)
{
	if (syscall_check_params(tf) == -1)
		return;

	if (!syscall_allow(tf))
		return;

	syscall_do(tf);
}

int trap_init(void)
{
	dune_register_pgflt_handler(pgflt_handler);
	dune_register_syscall_handler(&syscall_handler);

	return 0;
}
