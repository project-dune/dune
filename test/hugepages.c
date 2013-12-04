#include <fcntl.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <asm/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdarg.h>
#include <stdlib.h>

#include "libdune/dune.h"
#include "hugepages.h"

#define MAP_HUGE_SHIFT	26
#define MAP_HUGE_1GB	(30 << MAP_HUGE_SHIFT)

static int errors;

static void test(int ok, const char *msg, ...)
{
	va_list ap;
	va_start(ap, msg);
	vprintf(msg, ap);
	va_end(ap);
	errors += ok ? 0 : 1;
	puts(ok ? " OK" : " FAIL");
}

static int pte_big(ptent_t pte)
{
	return PTE_FLAGS(pte) & PTE_PS;
}

static int guest_page_order(ptent_t *root, unsigned long addr)
{
	int level;
	int offset;
	ptent_t entry;

	for (level = 3; level > 0; level--) {
		offset = PDX(level, addr);
		entry = root[offset];
		if (pte_big(entry))
			break;
		root = (ptent_t *)PTE_ADDR(entry);
	}
	return level;
}

static int host_page_order(int fd, ptent_t *root, unsigned long addr)
{
	int level;
	int offset;
	ptent_t entry;

	for (level = 3; level > 0; level--) {
		offset = PDX(level, addr);
		entry = (ptent_t)&root[offset];
		if (ioctl(fd, HUGEPAGES_READ_MEM, &entry) == -1) {
			fprintf(stderr, "FAIL: ioctl HUGEPAGES_READ_MEM\n");
			return -1;
		}
		if (pte_big(entry))
			break;
		root = (ptent_t *)PTE_ADDR(entry);
	}
	return level;
}

static void *prepare(char *title, void *addr, size_t size, int flags, int advise_huge, int perm)
{
	int ok;
	char *msg = "%s - %-16s";

	if (addr)
		flags |= MAP_FIXED;

	addr = mmap(addr, size, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE|flags, -1, 0);
	if (addr == MAP_FAILED) {
		perror("mmap");
		exit(1);
	}

	if (advise_huge) {
		if (madvise(addr, size, MADV_HUGEPAGE)) {
			perror("madvise");
			exit(1);
		}
	}
	ok = !dune_vm_map_phys(pgroot, addr, size, (void *)dune_mmap_addr_to_pa(addr), PERM_R | PERM_W | perm);
	test(ok, msg, title, "dune_vm_map_phys");
	*((char *)addr) = 0;

	return addr;
}

static void test_guest(char *title, void *addr, int expected_order)
{
	int order;

	order = guest_page_order((unsigned long *)get_cr3(), (unsigned long)addr);
	test(order == expected_order, "%s - %-16s", title, "guest");
}

static void test_host(char *title, void *addr, int expected_order, int fd)
{
	unsigned long cr3;
	int order;

	if (ioctl(fd, HUGEPAGES_GET_CR3, &cr3) == -1) {
		perror("ioctl(HUGEPAGES_GET_CR3)");
		exit(1);
	}
	order = host_page_order(fd, (unsigned long *)cr3, (unsigned long)addr);
	test(order == expected_order, "%s - %-16s", title, "host");
}

static void test_extended(char *title, void *addr, int expected_order, int fd)
{
	unsigned long eptp;
	int order;

	if (ioctl(fd, HUGEPAGES_GET_EPTP, &eptp) == -1) {
		perror("ioctl(HUGEPAGES_GET_EPTP)");
		exit(1);
	}
	order = host_page_order(fd, (unsigned long *)eptp, dune_mmap_addr_to_pa(addr));
	test(order == expected_order, "%s - %-16s", title, "extended");
}

int main(int argc, char *argv[])
{
	void *p4k, *p2m, *p1g, *p2m_trans, *p1g_trans;
	uintptr_t base;
	unsigned long align;
	int fd;

	int ret = dune_init_and_enter();
	if (ret) {
		fprintf(stderr, "Failed to enter dune mode.\n");
		exit(1);
	}

	fd = open("/dev/hugepages_mod", O_RDONLY);
	if (fd <= 0) {
		perror("open(/dev/hugepages_mod)");
		exit(1);
	}

	align = 1<<30;
	base = (mmap_base & ~(align - 1)) + align;

	p4k = prepare("4KB", NULL, 1<<12, 0, 0, 0);
	test_guest("4KB", p4k, 0);
	test_host("4KB", p4k, 0, fd);
	test_extended("4KB", p4k, 0, fd);

	p2m = prepare("2MB", (void *)(base+align*0), 1<<21, MAP_HUGETLB, 0, PERM_BIG);
	test_guest("2MB", p2m, 1);
	test_host("2MB", p2m, 1, fd);
	test_extended("2MB", p2m, 1, fd);

	p1g = prepare("1GB", (void *)(base+align*1), 1<<30, MAP_HUGETLB|MAP_HUGE_1GB, 0, PERM_BIG_1GB);
	test_guest("1GB", p1g, 2);
	test_host("1GB", p1g, 2, fd);
	test_extended("1GB", p1g, 2, fd);

	p2m_trans = prepare("2MB (transparent)", (void *)(base+align*2), 1<<21, 0, 1, PERM_BIG);
	test_guest("2MB (transparent)", p2m_trans, 1);
	test_host("2MB (transparent)", p2m_trans, 1, fd);
	test_extended("2MB (transparent)", p2m_trans, 1, fd);

	p1g_trans = prepare("1GB (transparent)", (void *)(base+align*3), 1<<30, 0, 1, PERM_BIG_1GB);
	test_guest("1GB (transparent)", p1g_trans, 2);
	test_host("1GB (transparent)", p1g_trans, 1, fd);
	test_extended("1GB (transparent)", p1g_trans, 1, fd);

	if (errors)
		printf("\n*** %d ERRORS FOUND ***\n", errors);
	else
		printf("\n*** SUCCESS ***\n");
	return 0;
}
