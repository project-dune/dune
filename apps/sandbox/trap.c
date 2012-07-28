/*
 * trap.c - handles system calls, page faults, and other traps
 */

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <asm/unistd_64.h>
#include <asm/prctl.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <utime.h>

#include "sandbox.h"

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

static int sys_uname(struct utsname *buf)
{
	if (check_extent((void *) buf, sizeof(struct utsname)))
		return -EFAULT;

	return get_err(uname(buf));
}

static int sys_arch_prctl(int cmd, unsigned long data)
{
	if (cmd == ARCH_GET_FS) {
		unsigned long *ptr = (unsigned long *) data;
		if (check_extent(ptr, sizeof(unsigned long)))
			return -EFAULT;
		*ptr = dune_get_user_fs();
		return 0;
	} else if (cmd == ARCH_SET_FS) {
		dune_set_user_fs(data);
		return 0;
	}

	return -EINVAL;
}

static int sys_open(const char *pathname, int flags)
{
	if (check_string(pathname))
		return -EFAULT;

	printf("opening file %s\n", pathname);
	int ret = open(pathname, flags);
	return get_err(ret);

	//return get_err(open(pathname, flags));
}

static int sys_close(int fd)
{
	if (fd < 3)
		return 0;
	return get_err(close(fd));
}

static ssize_t sys_read(int fd, void *buf, size_t count)
{
	if (check_extent(buf, count))
		return -EFAULT;

	return get_err(read(fd, buf, count));
}

static ssize_t sys_write(int fd, const void *buf, size_t count)
{
	if (check_extent(buf, count))
		return -EFAULT;

	return get_err(write(fd, buf, count));
}

static ssize_t sys_writev(int fd, const struct iovec *iov, int iovcnt)
{
	return get_err(writev(fd, iov, iovcnt));
}

static int sys_fstat(int fd, struct stat *buf)
{
	if (check_extent((void *) buf, sizeof(struct stat)))
		return -EFAULT;

	return get_err(fstat(fd, buf));
}

static int sys_lstat(const char *pathname, struct stat *buf)
{
	if (check_extent((void *) buf, sizeof(struct stat)))
		return -EFAULT;

	return get_err(lstat(pathname, buf));
}

static int sys_stat(const char *pathname, struct stat *buf)
{
	if (check_extent((void *) buf, sizeof(struct stat)))
		return -EFAULT;

	return get_err(stat(pathname, buf));
}

static off_t sys_lseek(int fd, off_t off, int whence)
{
	return get_err(lseek(fd, off, whence));
}

static int sys_fcntl(int fd, int cmd)
{
	if (cmd != F_GETFL)
		return -EINVAL;

	return get_err(fcntl(fd, F_GETFL));
}

static int sys_fchmod(int fd, mode_t mode)
{
	return get_err(fchmod(fd, mode));
}

static int sys_fchown(int fd, uid_t owner, gid_t group)
{
	return get_err(fchown(fd, owner, group));
}

static int sys_unlink(char *path)
{
	return get_err(unlink(path));
}

static int sys_utime(const char *path,
		     const struct utimbuf *times)
{
	return get_err(utime(path, times));
}

static void syscall_handler(struct dune_tf *tf)
{
	uint64_t syscall_num = tf->rax;
//	printf("got syscall #%ld\n", syscall_num);

	switch (syscall_num) {
	case __NR_uname:
		tf->rax = sys_uname((struct utsname *) ARG0(tf));
		break;

	case __NR_arch_prctl:
		tf->rax = sys_arch_prctl((int) ARG0(tf),
					 (unsigned long) ARG1(tf));
		break;

	case __NR_open:
		tf->rax = sys_open((char *) ARG0(tf), ARG1(tf));
		break;

	case __NR_close:
		tf->rax = sys_close(ARG0(tf));
		break;

	case __NR_read:
		tf->rax = sys_read(ARG0(tf), (void *) ARG1(tf),
				   (size_t) ARG2(tf));
		break;

	case __NR_write:
		tf->rax = sys_write(ARG0(tf), (void *) ARG1(tf),
				    (size_t) ARG2(tf));
		break;

	case __NR_writev:
		dune_dump_trap_frame(tf);
		tf->rax = sys_writev((int) ARG0(tf), (struct iovec *) ARG1(tf),
				     (int) ARG2(tf));
		break;

	case __NR_stat:
		tf->rax = sys_stat((char *) ARG0(tf),
				   (struct stat *) ARG1(tf));
		break;

	case __NR_fstat:
		tf->rax = sys_fstat(ARG0(tf), (struct stat *) ARG1(tf));
		break;

	case __NR_lstat:
		tf->rax = sys_lstat((char *) ARG0(tf),
				    (struct stat *) ARG1(tf));
		break;

	case __NR_lseek:
		tf->rax = sys_lseek(ARG0(tf), ARG1(tf), ARG2(tf));
		break;

	case __NR_fcntl:
		tf->rax = sys_fcntl((int) ARG0(tf), (int) ARG1(tf));
		break;

	case __NR_fchmod:
		tf->rax = sys_fchmod((int) ARG0(tf), (mode_t) ARG1(tf));
		break;

	case __NR_fchown:
		tf->rax = sys_fchown((int) ARG0(tf), (uid_t) ARG1(tf),
				     (gid_t) ARG2(tf));
		break;

	case __NR_unlink:
		tf->rax = sys_unlink((char *) ARG0(tf));
		break;

	case __NR_utime:
		tf->rax = sys_utime((char *) ARG0(tf),
				    (struct utimbuf *) ARG1(tf));
		break;

	case __NR_brk:
		tf->rax = umm_brk((unsigned long) ARG0(tf));
		break;

	case __NR_mmap:
		tf->rax = (unsigned long) umm_mmap((void *) ARG0(tf),
			(size_t) ARG1(tf), (int) ARG2(tf), (int) ARG3(tf),
			(int) ARG4(tf), (off_t) ARG5(tf));
		break;

	case __NR_mprotect:
		tf->rax = umm_mprotect((void *) ARG0(tf),
				       (size_t) ARG1(tf),
				       ARG2(tf));
		break;

	case __NR_munmap:
		tf->rax = umm_munmap((void *) ARG0(tf), (size_t) ARG1(tf)); 
		break;

	case __NR_exit_group:
	case __NR_exit:
		dune_ret_from_user(ARG0(tf));

	default:
//		printf("sandbox: unsupported syscall #%ld\n", syscall_num);
		dune_passthrough_syscall(tf); // FIXME: temporary stopgap
		//tf->rax = -ENOSYS;
	}

//	printf("ret is %ld\n", tf->rax);
}

int trap_init(void)
{
	dune_register_pgflt_handler(pgflt_handler);
	dune_register_syscall_handler(&syscall_handler);

	return 0;
}
