/*
 * umm.c - Memory management routines for the untrusted process
 * 
 * FIXME: Need some sort of balanced tree to determine which address
 * ranges are free. For now we just use a heuristic approach that
 * potentially wastes virtual address space, but should still
 * otherwise be safe.
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <stdlib.h>

#include "sandbox.h"

#define USE_BIG_MEM 0


// FIXME: these might need to be made thread safe
static size_t brk_len = 0;
static size_t mmap_len = 0;

static inline bool umm_space_left(size_t len)
{
	return (brk_len + mmap_len + len) < APP_MMAP_LEN;
}

static inline uintptr_t umm_get_map_pos(void)
{
	return mmap_base + APP_MMAP_BASE_OFF - mmap_len;
}

static inline int prot_to_perm(int prot)
{
	int perm = PERM_U;

	if (prot & PROT_READ)
		perm |= PERM_R;
	if (prot & PROT_WRITE)
		perm |= PERM_W;
	if (prot & PROT_EXEC)
		perm |= PERM_X;

	return perm;
}

static int umm_mmap_anom(void *addr, size_t len, int prot, bool big)
{
	int ret;
	void *mem;
	int flags = MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS;
	int perm = prot_to_perm(prot);

	if (big) {
		flags |= MAP_HUGETLB;
		perm |= PERM_BIG;
	}

	mem = mmap(addr, len, prot, flags, -1, 0);
	if (mem != addr)
		return -errno;

	ret = dune_vm_map_phys(pgroot, addr, len,
			      (void *) dune_va_to_pa(addr),
			      perm);
	if (ret) {
		munmap(addr, len);
		return ret;
	}

	return 0;
}

static int umm_mmap_file(void *addr, size_t len, int prot, int flags,
			 int fd, off_t offset)
{
	int ret;
	void *mem;

	mem = mmap(addr, len, prot,
		   MAP_FIXED | flags,
		   fd, offset);
	if (mem != addr)
		return -errno;

	ret = dune_vm_map_phys(pgroot, addr, len,
			      (void *) dune_va_to_pa(addr),
			      prot_to_perm(prot));
	if (ret) {
		munmap(addr, len);
		return ret;
	}

	return 0;
}

unsigned long umm_brk(unsigned long brk)
{
	size_t len;
	int ret;

	if (!brk)
		return mmap_base;

	if (brk < mmap_base)
		return -EINVAL;

	len = brk - mmap_base;

#if USE_BIG_MEM
	len = BIG_PGADDR(len + BIG_PGSIZE - 1);
#else
	len = PGADDR(len + PGSIZE - 1);
#endif

	if (!umm_space_left(len))
		return -ENOMEM;

	if (len == brk_len) {
		return brk;
	} else if (len < brk_len) {
//		printf("freeing heap %lx\n", brk_len - len);
		ret = munmap((void *) (mmap_base + len), brk_len - len);
		if (ret)
			return -errno;
		dune_vm_unmap(pgroot, (void *) (mmap_base + len),
			      brk_len - len);
	} else {
		ret = umm_mmap_anom((void *) (mmap_base + brk_len),
				    len - brk_len,
				    PROT_READ | PROT_WRITE, USE_BIG_MEM);
		if (ret)
			return ret;
	}

	brk_len = len;
	return brk;
}

unsigned long umm_map_big(size_t len, int prot)
{
	int ret;
	size_t full_len;
	void *addr;

//	printf("setting up a big page mapping of len %lx\n", len);

	full_len = BIG_PGADDR(len + BIG_PGSIZE - 1) +
		   BIG_PGOFF(umm_get_map_pos());
	addr = (void *) (umm_get_map_pos() - full_len);

	ret = umm_mmap_anom(addr, len, prot, 1);
	if (ret)
		return ret;

	mmap_len += full_len;
	return (unsigned long) addr;
}

unsigned long umm_mmap(void *addr, size_t len, int prot,
	       int flags, int fd, off_t offset)
{
	int adjust_mmap_len = 0;
	int ret;

#if USE_BIG_MEM
	if (len >= BIG_PGSIZE && (flags & MAP_ANONYMOUS) && !addr)
		return umm_map_big(len, prot);
#endif

	if (!addr) {
		if (!umm_space_left(len))
			return -ENOMEM;
		adjust_mmap_len = 1;
		addr = (void *) umm_get_map_pos() - PGADDR(len + PGSIZE - 1);	
	} else if (!mem_ref_is_safe(addr, len))
		return -EINVAL;

	if (flags & MAP_ANONYMOUS) {
		ret = umm_mmap_anom(addr, len, prot, 0);
		if (ret)
			return ret;
	} else if (fd > 0) {
		ret = umm_mmap_file(addr, len, prot, flags, fd, offset);
		if (ret)
			return ret;
	} else
		return -EINVAL;

	if (adjust_mmap_len)
		mmap_len +=  PGADDR(len + PGSIZE - 1);

	return (unsigned long) addr;
	
}

int umm_munmap(void *addr, size_t len)
{
	int ret;

	if (!mem_ref_is_safe(addr, len))
		return -EACCES;

	ret = munmap(addr, len);
	if (ret) {
		printf("hack to unmap big pages %p len %lx\n", addr, len);
		ret = munmap(addr, BIG_PGADDR(len + BIG_PGSIZE - 1));
		if (ret)
			return -errno;
		dune_vm_unmap(pgroot, addr, BIG_PGADDR(len + BIG_PGSIZE - 1));
		return 0;
	}

	dune_vm_unmap(pgroot, addr, len);

	return 0;
	
}

int umm_mprotect(void *addr, size_t len, unsigned long prot)
{
	int ret;

	if (!mem_ref_is_safe(addr, len))
		return -EACCES;

	ret = mprotect(addr, len, prot);
	if (ret)
		return -errno;

	ret = dune_vm_mprotect(pgroot, addr, len, prot_to_perm(prot));
	assert(!ret);

	return 0;
}

void *umm_shmat(int shmid, void *addr, int shmflg)
{
	struct shmid_ds shm;
	unsigned long len;
	void *mem;
	int ret;
	int perm;
	int prot = PROT_READ;
	int adjust_mmap_len = 0;

	if (!(shmflg & SHM_RDONLY))
		prot |= PROT_WRITE;

	perm = prot_to_perm(prot);

	if (shmctl(shmid, IPC_STAT, &shm) == -1)
		return (void*) -1;

	len = shm.shm_segsz;

	if (!addr) {
		if (!umm_space_left(len))
			return (void*) -ENOMEM;
		adjust_mmap_len = 1;
		addr = (void *) umm_get_map_pos() - PGADDR(len + PGSIZE - 1);	
	} else if (!mem_ref_is_safe(addr, len))
		return (void*) -EINVAL;

	mem = shmat(shmid, addr, shmflg);
	if (mem != addr)
		return (void*) (long) -errno;

	ret = dune_vm_map_phys(pgroot, addr, len,
			      (void *) dune_va_to_pa(addr),
			      perm);
	if (ret) {
		shmdt(addr);
		return (void*) (long) ret;
	}

	if (adjust_mmap_len)
		mmap_len +=  PGADDR(len + PGSIZE - 1);

	return addr;
}

void *umm_mremap(void *old_address, size_t old_size, size_t new_size, int flags,
		 void *new_address)
{
	int adjust_mmap_len = 0;
	void *ret;

	if (!mem_ref_is_safe(old_address, old_size))
		return (void*) -EACCES;

	if (flags & MREMAP_FIXED) {
		if (!mem_ref_is_safe(new_address, new_size))
			return (void*) -EACCES;
	} else {
		if (!umm_space_left(new_size))
			return (void*) -ENOMEM;
		adjust_mmap_len = 1;
		new_address = (void *) umm_get_map_pos() - PGADDR(new_size + PGSIZE - 1);	
	}

	/* XXX add support in future */
	if (!(flags & MREMAP_MAYMOVE))
		return (void*) -EINVAL;

	flags |= MREMAP_FIXED | MREMAP_MAYMOVE;

	ret = mremap(old_address, old_size, new_size, flags, new_address);
	if (ret != new_address)
		return (void*) (long) -errno;

        if (adjust_mmap_len)
                mmap_len +=  PGADDR(new_size + PGSIZE - 1);

	dune_vm_unmap(pgroot, old_address, old_size);

        if (dune_vm_map_phys(pgroot, new_address, new_size,
                              (void *) dune_va_to_pa(new_address),
                              prot_to_perm(PROT_READ | PROT_WRITE))) {
		printf("help me!\n");
		exit(1);
	}

	return ret;
}

int umm_alloc_stack(uintptr_t *stack_top)
{
	int ret;
	uintptr_t base = umm_get_map_pos();

	if (!umm_space_left(APP_STACK_SIZE))
		return -ENOMEM;

	// Make sure the last page is left unmapped so hopefully
	// we can at least catch most common stack overruns.
	// If not, the untrusted code is only harming itself.
	ret = umm_mmap_anom((void *) (PGADDR(base) -
			    APP_STACK_SIZE + PGSIZE),
			    APP_STACK_SIZE - PGSIZE,
			    PROT_READ | PROT_WRITE, 0);
	if (ret)
		return ret;

	mmap_len += APP_STACK_SIZE + PGOFF(base);
	*stack_top = PGADDR(base);
	return 0;
}
