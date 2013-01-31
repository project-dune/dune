#define _GNU_SOURCE

#include <stdio.h>
#include <errno.h>
#include <string.h>

#include "sandbox.h"

#define NUM_AUX 13

struct elf_data {
	uintptr_t entry;
	Elf64_Phdr *phdr;
	int phnum;
};

static int process_elf_ph(struct dune_elf *elf, Elf64_Phdr *phdr)
{
	int ret;
	int perm = PERM_U;
	off_t off;

	if (phdr->p_type == PT_INTERP) {
		printf("sandbox: .interp sections are not yet supported\n");
		return -EINVAL;
	}

	if (phdr->p_type != PT_LOAD)
		return 0; // continue to next section
#if 0
	printf("sandbox: loading segment - va 0x%09lx, len %lx\n",
	       phdr->p_vaddr, phdr->p_memsz);
#endif
	if (elf->hdr.e_type == ET_DYN)
		off = LOADER_VADDR_OFF;
	else
		off = 0;

	if (phdr->p_vaddr + off + phdr->p_memsz > APP_MAX_ELF_VADDR ||
	    phdr->p_memsz > APP_MAX_ELF_VADDR || // for overflow
	    phdr->p_filesz > phdr->p_memsz) {
		printf("sandbox: segment address is insecure\n");
		return -EINVAL;
	}

	ret = dune_vm_map_phys(pgroot,
			      (void *) (phdr->p_vaddr + off),
			      phdr->p_memsz,
			      (void *) (phdr->p_vaddr + off),
			      PERM_R | PERM_W);
	if (ret) {
		printf("sandbox: segment mapping failed\n");
		return ret;
	}

	ret = dune_elf_load_ph(elf, phdr, off);
	if (ret) {
		printf("sandbox: segment load failed\n");
		return ret;
	}

	if (phdr->p_flags & PF_X)
		perm |= PERM_X;
	if (phdr->p_flags & PF_R)
		perm |= PERM_R;
	if (phdr->p_flags & PF_W)
		perm |= PERM_W;

	ret = dune_vm_mprotect(pgroot, (void *) (phdr->p_vaddr + off),
			      phdr->p_memsz, perm);
	if (ret) {
		printf("sandbox: segment protection failed\n");
		return ret;
	}

	return 0;
}

static int load_elf(const char *path, struct elf_data *data)
{
	int ret;
	struct dune_elf elf;

	ret = dune_elf_open(&elf, path);
	if (ret)
		return ret;

	if (elf.hdr.e_type != ET_EXEC &&
	    elf.hdr.e_type != ET_DYN) {
		printf("sandbox: ELF is not a valid type\n");
		ret = -EINVAL;
		goto out;
	}

	ret = dune_elf_iter_ph(&elf, &process_elf_ph);
	if (ret)
		goto out;


	if (elf.hdr.e_type == ET_DYN) {
		data->entry = (uintptr_t) (elf.hdr.e_entry + LOADER_VADDR_OFF);
		data->phdr = (Elf64_Phdr *) (elf.hdr.e_phoff + LOADER_VADDR_OFF);
	} else {
		data->entry = (uintptr_t) elf.hdr.e_entry;
		// FIXME: could probably make this more robust
		data->phdr = (Elf64_Phdr *) (elf.hdr.e_phoff + 0x400000);
	}
	data->phnum = elf.hdr.e_phnum;

out:
	dune_elf_close(&elf);
	return ret;
}

static void count_args(char *argv[], int *argc, size_t *arglen)
{
	int i = 0;

	while (argv[i])
		i++;

	*argc = i;
	if (!i) {
		*arglen = 0;
		return;
	}

	*arglen = (size_t) rawmemchr(argv[i - 1], 0) -
		  (size_t) argv[0] + 1;
}

static Elf64_auxv_t * find_aux_entry(Elf64_auxv_t *aux, uint64_t type)
{
	while (aux->a_type) {
		if (aux->a_type == type)
			return aux;
		aux++;
	}

	return NULL;
}

static inline void copy_aux(Elf64_auxv_t *ref, Elf64_auxv_t *cur, uint64_t type)
{
	Elf64_auxv_t *found;

	cur->a_type = type;
	found = find_aux_entry(ref, type);
	assert(found);
	cur->a_un.a_val = found->a_un.a_val;

}

static void
setup_aux(Elf64_auxv_t *ref, Elf64_auxv_t *cur, struct elf_data data)
{

	copy_aux(ref, cur, AT_HWCAP);
	cur++;
	copy_aux(ref, cur, AT_PAGESZ);
	cur++;
	copy_aux(ref, cur, AT_CLKTCK);
	cur++;
	cur->a_type = AT_PHDR;
	cur->a_un.a_val = (uintptr_t) data.phdr;
	cur++;
	cur->a_type = AT_PHNUM;
	cur->a_un.a_val = data.phnum;
	cur++;
	copy_aux(ref, cur, AT_FLAGS);
	cur++;
	cur->a_type = AT_ENTRY;
	cur->a_un.a_val = data.entry;
	cur++;
	// FIXME: Should we allow UID to pass through?
	copy_aux(ref, cur, AT_UID);
	cur++;
	copy_aux(ref, cur, AT_EUID);
	cur++;
	copy_aux(ref, cur, AT_GID);
	cur++;
	copy_aux(ref, cur, AT_EGID);
	cur++;
	cur->a_type = AT_SECURE;
	cur->a_un.a_val = 0;
	cur++;

	/*
	 * FIXME: Dumb linux distros use __ASSUME_AT_RANDOM which requires
	 * this to be filled. This is not secure we need to map in a page
	 * with 16 random bytes.
	 */
	cur->a_type = AT_RANDOM;
	cur->a_un.a_val = (uintptr_t) data.phdr;
	cur++;

	cur->a_type = 0; // aux end
}

static uintptr_t
setup_arguments(uintptr_t sp, const char *path,
		char *argv[], char*envv[],
		struct elf_data data)
{
	char *data_ptr;
	uintptr_t *arg_ptr;
	Elf64_auxv_t *aux_ptr;
	size_t tmp, len = 0;
	int argc, envc, i;

	// determine data pointer
	count_args(argv, &argc, &tmp);
	len += tmp;
	count_args(envv, &envc, &tmp);
	len += tmp;
	len += strlen(path) + 1;
	data_ptr = (char *) sp - len;

	// determine aux pointer
	aux_ptr = (Elf64_auxv_t *) &envv[envc + 1];
	len += sizeof(Elf64_auxv_t) * NUM_AUX;

	// determine argument pointer
	len += (argc + envc + 4) * sizeof(uintptr_t);

	// The System V AMD64 ABI requires 16-byte stack alignment. We go
	// with 32-bytes to be extra conservative (e.g. in case of AVX)
	len = (len + 0x1f) & ~0x1f;

	arg_ptr = (uintptr_t *) (sp - len);
	*arg_ptr = argc + 1;
	arg_ptr++;

	// setup application name argument
	*arg_ptr = (uintptr_t) data_ptr;
	arg_ptr++;
	data_ptr = stpcpy(data_ptr, path) + 1;

	// setup remaining arguments
	for (i = 0; i < argc; i++) {
		*arg_ptr = (uintptr_t) data_ptr;
		arg_ptr++;
		data_ptr = stpcpy(data_ptr, argv[i]) + 1;
	}
	*arg_ptr = (uintptr_t) NULL; // arg end
	arg_ptr++;

	// setup environment
	for (i = 0; i < envc; i++) {
		*arg_ptr = (uintptr_t) data_ptr;
		arg_ptr++;
		data_ptr = stpcpy(data_ptr, envv[i]) + 1;
	}
	*arg_ptr = (uintptr_t) NULL; // env end
	arg_ptr++;

	// setup aux entries
	setup_aux(aux_ptr, (Elf64_auxv_t *) arg_ptr, data);

	return sp - len;
}

static int run_app(uintptr_t sp, uintptr_t e_entry)
{
	struct dune_tf tf;

	memset(&tf, 0, sizeof(struct dune_tf));
	tf.rip = e_entry;
	tf.rsp = sp;
	tf.rflags = 0x0;

	return dune_jump_to_user(&tf);
}

extern char **environ;

int boxer_main(int argc, char *argv[])
{
	int ret;
	uintptr_t sp;
	struct elf_data data;

	if (argc < 2)
		return -EINVAL;

	/* XXX needed.  Probably does some libc stuff */
	printf(" \b"); 

//	printf("%s\n", environ[0]);

	ret = dune_init(0);
	if (ret) {
		printf("sandbox: failed to initialize Dune\n");
		return ret;
	}

	ret = dune_enter();
	if (ret) {
		printf("sandbox: failed to enter Dune mode\n");
		return ret;
	}

	ret = load_elf(argv[1], &data);
	if (ret)
		return ret;

//	printf("sandbox: entry addr is %lx\n", data.entry);

	dune_set_user_fs(0); // default starting fs

	ret = trap_init();
	if (ret) {
		printf("failed to initialize trap handlers\n");
		return ret;
	}

	ret = umm_alloc_stack(&sp);
	if (ret) {
		printf("failed to alloc stack\n");
		return ret;
	}

	sp = setup_arguments(sp, argv[1], &argv[2], environ, data);
	if (!sp) {
		printf("failed to setup arguments\n");
		return -EINVAL;
	}

	ret = run_app(sp, data.entry);

	return ret;
}
