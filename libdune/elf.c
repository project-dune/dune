#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

#include "dune.h"
#include "elf.h"

#define MAX_SNAME 40
#define MAX_SHNUM 100
#define MAX_PHNUM 40

static int elf_read(struct dune_elf *elf, void *dst, int len, int off)
{
	int rd;

	if (elf->mem == NULL)
		return pread(elf->fd, dst, len, off);
		
	rd = elf->len - off;
	
	if (rd <= 0)
		return 0;

	if (len < rd)
		rd = len;

	memcpy(dst, &elf->mem[off], rd);

	return rd;
}

/**
 * dune_elf_load_ph - a utility function to map a .LOAD region into program memory
 * @elf: elf data
 * @phdr: the program header
 * 
 * Returns 0 on success, otherwise failure.
 */
int dune_elf_load_ph(struct dune_elf *elf, Elf64_Phdr *phdr, off_t off)
{
	void *ptr;
	int prot = PROT_NONE;

	if (phdr->p_type != PT_LOAD)
		return -EINVAL;
	if (phdr->p_filesz > phdr->p_memsz)
		return -EINVAL;

	if (phdr->p_flags & PF_X)
		prot |= PROT_EXEC;
	if (phdr->p_flags & PF_R)
		prot |= PROT_READ;
	if (phdr->p_flags & PF_W)
		prot |= PROT_WRITE;

	ptr = mmap((void *) (PGADDR(phdr->p_vaddr) + off),
		   phdr->p_filesz + PGOFF(phdr->p_vaddr),
		   prot, MAP_FIXED | MAP_PRIVATE,
		   elf->fd, PGADDR(phdr->p_offset));
	if (ptr != (void *) (PGADDR(phdr->p_vaddr) + off))
		return -ENOMEM;

	if (phdr->p_memsz > phdr->p_filesz) {
		unsigned long start = phdr->p_vaddr + phdr->p_filesz + off;
		unsigned long map_start = PGADDR(start + PGSIZE - 1);
		unsigned long zero_len = phdr->p_memsz - phdr->p_filesz;
		int mod_prot = !(prot & PROT_WRITE);

		// this is really stupid, but basically we have
		// to manually zero the bits that aren't page aligned :(
		if (start < map_start) {
			if (mod_prot &&
			    mprotect((void *) (map_start - PGSIZE),
				     PGSIZE, prot | PROT_WRITE))
				return -ENOMEM;

			memset((void *) start, 0, map_start - start);

			if (mod_prot &&
			    mprotect((void *) (map_start - PGSIZE),
				     PGSIZE, prot))
				return -ENOMEM;
		}

		ptr = mmap((void *) map_start, zero_len, prot,
			   MAP_ANON | MAP_FIXED | MAP_PRIVATE, -1, 0);
		if (ptr != (void *) map_start)
			return -ENOMEM;
	}

	return 0;
}

static int elf_open_phs(struct dune_elf *elf)
{
	int ret;
	size_t len;
	Elf64_Phdr *phdr;

	if (elf->hdr.e_phentsize != sizeof(Elf64_Phdr)) {
		printf("elf: unexpected phdr size\n");
		return -EINVAL;
	}

	if (elf->hdr.e_phnum > MAX_PHNUM) // security check
		return -EINVAL;

	len = elf->hdr.e_phnum * elf->hdr.e_phentsize;
	phdr = malloc(len);
	if (!phdr)
		return -ENOMEM;

	ret = pread(elf->fd, (void *) phdr, len, elf->hdr.e_phoff);
	if (ret != len) {
		printf("elf: failed to read program header table\n");
		free(phdr);
		return -EIO;
	}

	elf->phdr = phdr;

	return 0;
}

/**
 * dune_elf_iter_ph - iterates over each program header
 * @elf: elf data
 * @cb: a function callback called for each program header
 * 
 * Returns 0 on success, otherwise failure. If a callback
 * returns an error code, it gets propogated to the return
 * value.
 */
int dune_elf_iter_ph(struct dune_elf *elf, dune_elf_phcb cb)
{
	int i, ret;

	if (elf->phdr == NULL) {
		ret = elf_open_phs(elf);
		if (ret < 0)
			return ret;
	}

	for (i = 0; i < elf->hdr.e_phnum; i++) {
		ret = cb(elf, &elf->phdr[i]);
		if (ret)
			return ret;
	}

	return 0;
}

static int elf_open_shs(struct dune_elf *elf)
{
	int ret;
	size_t len;
	Elf64_Shdr *shdr;
	size_t strtablen;
	char *strtab;

	if (elf->hdr.e_shentsize != sizeof(Elf64_Shdr)) {
		printf("elf: unexpected shdr size\n");
		return -EINVAL;
	}

	if (elf->hdr.e_shnum > MAX_SHNUM) // security check
		return -EINVAL;

	len = elf->hdr.e_shnum * elf->hdr.e_shentsize;
	shdr = malloc(len);
	if (!shdr)
		return -ENOMEM;

	ret = elf_read(elf, (void *) shdr, len, elf->hdr.e_shoff);
	if (ret != len) {
		printf("elf: failed to read section header table\n");
		free(shdr);
		return -EIO;
	}

	if (elf->hdr.e_shstrndx > elf->hdr.e_shnum) {
		free(shdr);
		return -EINVAL;
	}
	if (shdr[elf->hdr.e_shstrndx].sh_type != SHT_STRTAB) {
		printf("elf: invalid section type for string table\n");
		free(shdr);
		return -EINVAL;
	}
	strtablen = shdr[elf->hdr.e_shstrndx].sh_size;
	// Security check?
	strtab = malloc(strtablen);
	if (!strtab) {
		free(shdr);
		return -ENOMEM;
	}
	ret = elf_read(elf, (void *) strtab, strtablen,
			    shdr[elf->hdr.e_shstrndx].sh_offset);
	if (ret != strtablen) {
		printf("elf: failed to read section header string table\n");
		free(shdr);
		free(strtab);
		return -EIO;
	}

	elf->shdr = shdr;
	elf->shdrstr = strtab;

	return 0;
}

/**
 * dune_elf_iter_sh - iterates over each section header
 * @elf: elf data
 * @cb: a function callback called for each section header
 * 
 * Returns 0 on success, otherwise failure. If a callback
 * returns an error code, it gets propogated to the return
 * value.
 */
int dune_elf_iter_sh(struct dune_elf *elf, dune_elf_shcb cb)
{
	int i, ret;

	if (elf->shdr == NULL) {
		ret = elf_open_shs(elf);
		if (ret < 0)
			return ret;
	}

	for (i = 0; i < elf->hdr.e_shnum; i++) {
		char *sname = elf->shdrstr + elf->shdr[i].sh_name;
		// XXX: Check offset and length
		if (strnlen(sname, MAX_SNAME) == MAX_SNAME) {
			dune_printf("elf: section name too long\n");
			return -EINVAL;
		}

		ret = cb(elf, sname, i, &elf->shdr[i]);
		if (ret)
			return ret;
	}

	return 0;
}

static int do_elf_open(struct dune_elf *elf)
{
	Elf64_Ehdr hdr;
	int ret;

	ret = elf_read(elf, (void *) &hdr, sizeof(Elf64_Ehdr), 0);
	if (ret != sizeof(Elf64_Ehdr)) {
		printf("elf: failed to read header\n");
		ret = -EIO;
		goto out;
	}

	if (hdr.e_ident[EI_MAG0] != ELFMAG0 ||
	    hdr.e_ident[EI_MAG1] != ELFMAG1 ||
	    hdr.e_ident[EI_MAG2] != ELFMAG2 ||
	    hdr.e_ident[EI_MAG3] != ELFMAG3 ||
	    hdr.e_ident[EI_CLASS] != ELFCLASS64 ||
	    hdr.e_ident[EI_DATA] != ELFDATA2LSB ||
	    hdr.e_ident[EI_VERSION] != EV_CURRENT ||
	    hdr.e_version != EV_CURRENT) {
		printf("elf: failed image sanity check\n");
		ret = -EINVAL;
		goto out;
	}

	if (hdr.e_machine != EM_X86_64) {
		printf("elf: unsupported architecture\n");
		ret = -EINVAL;
		goto out;
	}

	elf->hdr = hdr;
	elf->phdr = NULL;
	elf->shdr = NULL;
	elf->shdrstr = NULL;
	return 0;

out:
	dune_elf_close(elf);
	return ret;
}

/**
 * dune_elf_open - Open an elf binary
 * @elf: dune_elf object
 * @path: file path to the elf object
 *
 * Returns: 0 on success, otherwise failure.
 */
int dune_elf_open(struct dune_elf *elf, const char *path)
{
	int fd;

	fd = open(path, O_RDONLY);
	if (fd <= 0) {
		printf("elf: unable to open '%s'\n", path);
		return -EIO;
	}

	elf->fd  = fd;
	elf->mem = NULL;
	elf->len = 0;

	return do_elf_open(elf);
}

int dune_elf_open_mem(struct dune_elf *elf, void *mem, int len)
{
	elf->fd  = -1;
	elf->mem = mem;
	elf->len = len;

	return do_elf_open(elf);
}

/**
 * dune_elf_close - Close an elf object.
 * @elf: dune_elf object
 */
int dune_elf_close(struct dune_elf *elf)
{
	if (elf->phdr != NULL) {
		free(elf->phdr);
		elf->phdr = NULL;
	}
	if (elf->shdr != NULL) {
		free(elf->shdr);
		elf->shdr = NULL;
	}
	if (elf->shdrstr != NULL) {
		free(elf->shdrstr);
		elf->shdrstr = NULL;
	}

	if (elf->mem == NULL)
		close(elf->fd);

	return 0;
}

static const char *ShdrTypes[SHT_NUM] = {
	"NULL", "PROGBITS", "SYMTAB", "STRTAB", "RELA", "HASH", "DYNAMIC",
	"NOTE", "NOBITS", "REL", "SHLIB", "DYNSYM", "INIT_ARRAY", "FINI_ARRAY",
	"PREINIT_ARRAY", "GROUP", "SYMTAB_SHNDX",
};

static int elf_dump_sh(struct dune_elf *elf,
		       const char *sname,
		       int snum,
		       Elf64_Shdr *shdr)
{
	const char *type = "UNKNOWN";
	if (shdr->sh_type < SHT_NUM)
		type = ShdrTypes[shdr->sh_type];

	dune_printf("  [%2d] %-16s %-16s %016llx %08x\n",
			   snum, sname, type, shdr->sh_addr, shdr->sh_offset);
	dune_printf("       %016llx %016llx %c%c%c%c%c %4d %4d %5d\n",
			   shdr->sh_size, shdr->sh_entsize,
			   shdr->sh_flags & SHF_WRITE ? 'W' : ' ',
			   shdr->sh_flags & SHF_ALLOC ? 'A' : ' ',
			   shdr->sh_flags & SHF_EXECINSTR ? 'X' : ' ',
			   shdr->sh_flags & SHF_MERGE ? 'M' : ' ',
			   shdr->sh_flags & SHF_STRINGS ? 'S' : ' ',
			   shdr->sh_link, shdr->sh_info, shdr->sh_addralign);

	return 0;
}

static const char *PhdrType[PT_NUM] = {
	"NULL", "LOAD", "DYNAMIC", "INTERP", "NOTE", "SHLIB", "PHDR", "TLS",
};

static int elf_dump_ph(struct dune_elf *elf, Elf64_Phdr *phdr)
{
	const char *type = "UNKNOWN";

	if (phdr->p_type < PT_NUM)
		type = PhdrType[phdr->p_type];

	dune_printf("  %-20s 0x%016llx 0x%016llx 0x%016llx\n",
			   type, phdr->p_offset,
			   phdr->p_vaddr, phdr->p_paddr);
	dune_printf("  %-20s 0x%016llx 0x%016llx  %c%c%c    %x\n",
			   "", phdr->p_filesz, phdr->p_memsz,
			   phdr->p_flags & PF_R ? 'R' : ' ',
			   phdr->p_flags & PF_W ? 'W' : ' ',
			   phdr->p_flags & PF_X ? 'X' : ' ',
			   phdr->p_align);

	return 0;
}

/**
 * dune_elf_dump - Dumps an elf binary program headers and segments
 * @elf: dune_elf object
 * 
 * Returns: 0 on success, otherwise failure.
 */
int dune_elf_dump(struct dune_elf *elf)
{
	int ret = 0;

	dune_printf("--- ELF Dump ---\n");

	// XXX: Dump Header

	dune_printf("Section Headers:\n");
	dune_printf("  [Nr] %-16s %-16s %-16s %s\n",
			   "Name", "Type", "Address", "Offset");
	dune_printf("       %-16s %-16s %s %s %s  %s\n",
			   "Size", "EntSize", "Flags", "Link", "Info", "Align");
	if ((ret = dune_elf_iter_sh(elf, &elf_dump_sh))) {
		printf("elf: failed to dump section headers\n");
		goto out;
	}

	dune_printf("Program Headers:\n");
	dune_printf("  %-20s %-18s %-18s %s\n",
			   "Type", "Offset", "VirtAddr", "PhysAddr");
	dune_printf("  %-20s %-18s %-18s %s   %s\n",
			   "", "FileSiz", "MemSize", "Flags", "Align");
	if ((ret = dune_elf_iter_ph(elf, &elf_dump_ph))) {
		printf("elf: failed to dump program headers\n");
		goto out;
	}

out:
	return ret;
}


