#include <sys/syscall.h>
#include <sys/mman.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <err.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

#include "sthread.h"
#include "dune.h"

#define STACK_SIZE	(4096 * 10)
#define TAG_SIZE	(4096 * 10)

enum {
	ST_RUNNING	= 0,
	ST_ZOMBIE,
	ST_DEAD,
};

struct sthread {
	int		st_id;
	int		st_state;
	void		*st_ret;
	void		*st_stack;
	ptent_t		*st_pgroot;
	struct dune_tf	st_tf;
	sc_t		st_sc;
	unsigned char	*st_writable;
	unsigned long	st_walk;
	struct sthread	*st_next;
};

static int _sthread_id;

static struct segment {
	unsigned long	s_start;
	unsigned long	s_end;
	unsigned long	s_len;
	unsigned int	s_flags;
	char		s_txt[1024];
	struct segment	*s_next;
} _segments;

static unsigned char *_checkpointed_mem;
static int _checkpointed_size;

struct tag {
        int             t_id;
        void            *t_buf;
        unsigned char   *t_p;
        int             t_len;
        struct tag      *t_next;
} _tags;

static int _tag_id;

static struct kstate {
	struct sthread	*ks_current;
	struct sthread	ks_sthreads;
} *_kstate;

static void *xmalloc(size_t sz)
{
	void *x = malloc(sz);

	if (!x)
		err(1, "malloc()");

	return x;
}

static void *kmalloc(int sz)
{
	/* XXX */
	static int _tag = -1;
	void *x;

	if (_tag == -1)
		_tag = tag_new();

	x = smalloc(_tag, sz);
	if (!x)
		errx(1, "kmalloc()");

	return x;
}

static int walk_recycle(const void *arg, ptent_t *ptep, void *va)
{
	struct sthread *s = (void*) arg;
	unsigned char *pa = &s->st_writable[s->st_walk];
	unsigned char *orig = &_checkpointed_mem[s->st_walk];

	s->st_walk += 4096;

	if (!(*ptep & PTE_D))
		return 0;

//	printf("Dirty %p\n", va);

	memcpy(pa, orig, 4096);

	*ptep = *ptep & ~PTE_D;

	return 0;
}

static int walk_recycle_stack(const void *arg, ptent_t *ptep, void *va)
{
	struct sthread *s = (void*) arg;
	unsigned char *pa = (unsigned char*) s->st_stack + s->st_walk;

	s->st_walk += 4096;

	if (!(*ptep & PTE_D))
		return 0;

//	printf("Dirty stack %p\n", va);

	memset(pa, 0, 4096);
//	*ptep = *ptep & ~PTE_D;

	return 0;
}

static void recycle(struct sthread *s)
{
	struct segment *seg = _segments.s_next;

	s->st_walk = 0;

	while (seg) {
		if (seg->s_flags & PROT_WRITE) {
			dune_vm_page_walk(s->st_pgroot, (void*) seg->s_start,
					  (void*) seg->s_end - 4096,
					  walk_recycle, s);
		}

		seg = seg->s_next;
	}

	s->st_walk = 0;
	dune_vm_page_walk(s->st_pgroot, (void*) s->st_stack, 
			  (void*) (s->st_stack + STACK_SIZE - 4096),
			  walk_recycle_stack, s);
}

static int has_fd_perm(struct sthread *s, int fd, int perm)
{
	int i;

	for (i = 0; i < sizeof(s->st_sc.sc_fd) / sizeof(*s->st_sc.sc_fd); i++) {
		int f = s->st_sc.sc_fd[i];

		if (f == 0)
			break;

		if ((f >> 8) == fd) {
			if ((f & 0xf) & perm)
				return 1;
			break;
		}
	}

	return 0;
}

static int can_do_sys(struct sthread *st, int sysno)
{
	sc_t *sc = &st->st_sc;
	int pos = sysno / 8;

	/* some defaults */
	switch (sysno) {
	case 666:
	case SYS_read:
	case SYS_write:
		return 1;
	}

//	dune_printf("POS %d sys %d\n", pos, sysno);

	if (pos < 0 || pos > (sizeof(sc->sc_sys) / sizeof(*sc->sc_sys)))
		errx(1, "can_do_sys");

	return sc->sc_sys[pos] & (1 << (sysno % 8));
}

static void schedule(struct dune_tf *tf)
{
	struct sthread *s = _kstate->ks_sthreads.st_next;

#if 0
	dune_printf("resched %d [tf %p]\n",
		    _kstate->ks_current ? _kstate->ks_current->st_id : -1, tf);
#endif

	while (s) {
		if (s != _kstate->ks_current 
		    && s->st_state == ST_RUNNING)
			break;

		s = s->st_next;
	}

	if (s) {
//		dune_printf("Scheduling %d\n", s->st_id);

		_kstate->ks_current = s;
		load_cr3((unsigned long) s->st_pgroot | CR3_NOFLUSH | s->st_id);
		dune_passthrough_syscall(&s->st_tf);
		dune_jump_to_user(&s->st_tf); /* XXX need to restore EBP */
		load_cr3((unsigned long) pgroot | CR3_NOFLUSH | 0);
		_kstate->ks_current = NULL;
		return;
	}

	/* try master */
	if (!s && tf) {
//		dune_printf("Scheduling master\n");
                dune_ret_from_user(-1);
		return;
	}

	dune_printf("damn... gotta schedule the same dude\n");
	abort();
}

static int walk_check_perm(const void *arg, ptent_t *ptep, void *va)
{
	struct sthread *s = (void*) arg;

	if (!(*ptep & PTE_U))
		return 1;

	if (!(*ptep & PTE_P))
		return 1;

	if (!(*ptep & PTE_W))
		return 1;

//	dune_printf("Check addr VA %p PA %p\n", va, (void*) PTE_ADDR(*ptep));

	if (!s->st_walk) {
		unsigned long addr = PTE_ADDR(*ptep);

		if (addr >= 0x400000000)
			addr = addr + mmap_base - 0x400000000;

		s->st_walk = addr;
	}

	return 0;
}

static int has_mem_perm(struct sthread *s, void *ptr, unsigned long len)
{
	int rc;

	s->st_walk = 0;
	rc = dune_vm_page_walk(s->st_pgroot, ptr,
			       (void*) ((unsigned long) ptr + len),
			       walk_check_perm, s);

	return rc == 0;
}

static void syscall_handler(struct dune_tf *tf)
{
        int syscall_num = (int) tf->rax;
	struct sthread *current = _kstate->ks_current;
	int fd = -1, perm = -1;
	int rc;
	int need_resched = 0;
	unsigned long *ptr = NULL;
	unsigned long len = 0;

//	dune_printf("SYSCALL %d current %p\n", syscall_num, _kstate->ks_current);

	/* can we do the syscall? */
	if (!can_do_sys(current, syscall_num))
		goto __blocked;

	/* check FDs */
	switch (syscall_num) {
	case SYS_read:
		perm = PROT_READ;
		fd = (int) ARG0(tf);
		break;

	case SYS_write:
		perm = PROT_WRITE;
		fd = (int) ARG0(tf);
		break;

	case SYS_close:
		perm = PROT_WRITE;
		fd = (int) ARG0(tf);
		break;
	}

	if (perm != -1) {
		if (!has_fd_perm(current, fd, perm))
			goto __blocked;
	}

	/* check memory */
	switch (syscall_num) {
	case SYS_open:
		ptr = &tf->rdi;
		len = strlen((void*) *ptr); /* XXX */
		break;

	case SYS_write:
	case SYS_read:
		ptr = &tf->rsi;
		len = ARG2(tf);
		break;
	}

	if (ptr) {
		assert(current->st_walk);
		if (!has_mem_perm(current, (void*) *ptr, len))
			goto __blocked;

		/* XXX */
		*ptr = current->st_walk + (*ptr & 0xfff);
	}

	/* special treatment */
	switch (syscall_num) {
	case 666:
        	current->st_ret = (void*) ARG0(tf);
		recycle(current);
		current->st_state = ST_ZOMBIE;
                dune_ret_from_user((int) ARG0(tf));
		return;

	case SYS_read:
		need_resched = 1;
		break;

        case SYS_open:
                rc = open((char*) ARG0(tf), ARG1(tf), ARG2(tf), ARG3(tf));
                if (rc >= 0)
                        sc_fd_add(&current->st_sc, rc, PROT_READ | PROT_WRITE);

                tf->rax = rc;
		return;
	}

	if (need_resched) {
		memcpy(&current->st_tf, tf, sizeof(current->st_tf));
		schedule(tf);
		return;
	}

	dune_passthrough_syscall(tf);
	return;

__blocked:
	dune_printf("Blocked syscall %d\n", syscall_num);
	tf->rax = -EINVAL;
}

static void checkpoint_prepare(void)
{
	int fd, rd;
	char buf[4096 * 2];
	char *p, *p2;
	struct segment *seg = &_segments;
	int writable = 0;

	fd = open("/proc/self/maps", O_RDONLY);
	if (fd == -1)
		err(1, "open()");

	rd = read(fd, buf, sizeof(buf) - 1);
	if (rd <= 0)
		err(1, "read()");

	close(fd);
	buf[rd] = 0;

//	printf("%s\n", buf);

	p = buf;

	while (*p) {
		unsigned long start, end;
		char perm[16];
		struct segment *s;

		p2 = strchr(p, '\n');
		*p2++ = 0;

		if (sscanf(p, "%lx-%lx %s ", &start, &end, perm) != 3)
			err(1, "sscanf()");

//		printf("Start %lx end %lx perm %s\n", start, end, perm);

		/* XXX */
		if (strstr(p, "stack"))
			goto __next;

		s = xmalloc(sizeof(*s));
		memset(s, 0, sizeof(*s));
		s->s_start = start;
		s->s_end   = end;
		s->s_len   = end - start;

		if (perm[1] == 'w') {
			s->s_flags |= PROT_WRITE;
			writable += s->s_len;
		}

		if (perm[0] == 'r')
			s->s_flags |= PROT_READ;

		if (perm[3] == 'x')
			s->s_flags |= PROT_EXEC;

		snprintf(s->s_txt, sizeof(s->s_txt), p);

		seg->s_next = s;
		seg = s;
__next:
		p = p2;
	}

	printf("Writable mem %d (%d pages)\n", writable, writable / 4096);

	_checkpointed_size = writable;
	_checkpointed_mem = mmap(NULL, writable, PROT_READ | PROT_WRITE,
				 MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

	if (_checkpointed_mem == MAP_FAILED)
		err(1, "mmap()");
}

static void checkpoint_do(void)
{
	struct segment *seg;
	unsigned char *c;

	c = _checkpointed_mem;
	seg = _segments.s_next;

	/* checkpoint / copy memory */
	while (seg) {
		if (seg->s_flags & PROT_WRITE) {
			memcpy(c, (void*) seg->s_start, seg->s_len);
			c += seg->s_len;
		}

		seg = seg->s_next;
	}
}

int sthread_init(void)
{
	checkpoint_prepare();

	if (dune_init_and_enter())
		return -1;

        dune_register_syscall_handler(syscall_handler);

	_kstate = kmalloc(sizeof(*_kstate));

	checkpoint_do();

	return 0;
}

void sc_init(sc_t *sc)
{
	memset(sc, 0, sizeof(*sc));
}

static void sthread_trampoline(stcb_t cb, void *arg)
{       
        void *ret;

        ret = cb(arg);

        syscall(666, ret);
}

static int launch_sthread(struct sthread *s, stcb_t cb, void *arg)
{
	struct dune_tf tf;

        memset(&tf, 0, sizeof(tf));
        tf.rip = (unsigned long) sthread_trampoline;
        tf.rsp = (unsigned long) s->st_stack + STACK_SIZE - 8;
        tf.rflags = 0x02;

        tf.rdi = (unsigned long) cb;
        tf.rsi = (unsigned long) arg;

	s->st_state = ST_RUNNING;

	_kstate->ks_current = s;
	load_cr3((unsigned long) s->st_pgroot | CR3_NOFLUSH | s->st_id);
        dune_jump_to_user(&tf);
	load_cr3((unsigned long) pgroot | CR3_NOFLUSH | 0);
	_kstate->ks_current = NULL;

	return 0;
}

static int walk_remap(const void *arg, ptent_t *ptep, void *va)
{
	struct sthread *s = (void*) arg;
	unsigned char *pa = &s->st_writable[s->st_walk];

	s->st_walk += 4096;

	*ptep = dune_va_to_pa(pa) | PTE_P | PTE_W | PTE_U;

	return 0;
}

static int walk_protect(const void *arg, ptent_t *ptep, void *va)
{
	struct sthread *s = (void*) arg;
	struct segment *seg = _segments.s_next;
	unsigned long addr = (unsigned long) va;
	int i;

	/* default deny */
	*ptep &= ~PTE_U;

	/* read only stuff */
	while (seg) {
		if (addr >= seg->s_start && addr < seg->s_end) {
			if (!(seg->s_flags & PROT_WRITE))
				*ptep |= PTE_U;

			return 0;
		}

		seg = seg->s_next;
	}

	/* stack */
	if (addr >= (unsigned long) s->st_stack &&
	    addr < (unsigned long) s->st_stack + STACK_SIZE)
		*ptep |= PTE_U;

	/* tags */
	for (i = 0; i < sizeof(s->st_sc.sc_mem) / sizeof(*s->st_sc.sc_mem); i++)
	{
		unsigned long tag = s->st_sc.sc_mem[i];
		unsigned long a = tag & 0xfffffffffffffff0L;

		if (tag == 0)
			break;

		if (addr >= a && addr < (a + TAG_SIZE)) {
			*ptep |= PTE_U;

			if (!(tag & PROT_WRITE))
				*ptep &= ~PTE_W;

			return 0;
		}
	}

	return 0;
}

struct sthread *create_new_sthread(sc_t *sc)
{
	struct sthread *s;
	struct segment *seg = _segments.s_next;

	s = kmalloc(sizeof(*s));
	memset(s, 0, sizeof(*s));

	s->st_id = ++_sthread_id;
	assert(_sthread_id >= 0);

	printf("Creating a new sthread %d\n", s->st_id);

	s->st_next = _kstate->ks_sthreads.st_next;
	_kstate->ks_sthreads.st_next = s;

	memcpy(&s->st_sc, sc, sizeof(s->st_sc));

        s->st_stack = mmap(NULL, STACK_SIZE, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (s->st_stack == MAP_FAILED)
		err(1, "mmap()");

	s->st_writable = mmap(NULL, _checkpointed_size, PROT_READ | PROT_WRITE,
			      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (s->st_writable == MAP_FAILED)
		err(1, "mmap()");

	memcpy(s->st_writable, _checkpointed_mem, _checkpointed_size);

        s->st_pgroot = dune_vm_clone(pgroot);

	dune_vm_page_walk(s->st_pgroot, VA_START, VA_END, walk_protect, s);

	s->st_walk = 0;
	while (seg) {
		if (seg->s_flags & PROT_WRITE) {
			dune_vm_page_walk(s->st_pgroot, (void*) seg->s_start,
					  (void*) seg->s_end - 4096, walk_remap, s);
		}

		seg = seg->s_next;
	}

	return s;
}

int sthread_create(sthread_t *st, sc_t *sc, stcb_t cb, void *arg)
{
	struct sthread *s = _kstate->ks_sthreads.st_next;

	/* try to recycle */
	while (s) {
		if (s->st_state == ST_DEAD 
		    && memcmp(sc, &s->st_sc.sc_mem, sizeof(sc->sc_mem)) == 0) {
			memcpy(&s->st_sc, sc, sizeof(*sc));
			break;
		}

		s = s->st_next;
	}

	/* create a fresh one */
	if (!s)
		s = create_new_sthread(sc);

	*st = s->st_id;

	return launch_sthread(s, cb, arg);
}

int sthread_join(sthread_t st, void **ret)
{
	struct sthread *s = _kstate->ks_sthreads.st_next;

	while (s) {
		if (s->st_id == st)
			break;

		s = s->st_next;
	}

	if (!s)
		return -1;

	while (s->st_state != ST_ZOMBIE)
		schedule(NULL);

	if (s->st_state != ST_ZOMBIE)
		return -1;

	if (ret)
		*ret = s->st_ret;

	s->st_state = ST_DEAD;

	return 0;
}

tag_t tag_new(void)
{       
        struct tag *t;
        int len = TAG_SIZE;

        t = xmalloc(sizeof(*t));

        t->t_id = _tag_id++;

        t->t_buf = mmap(NULL, len, PROT_READ | PROT_WRITE,
                        MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

        if (t->t_buf == MAP_FAILED)
                err(1, "mmap()");

        t->t_p   = t->t_buf;                                                                                 
        t->t_len = len;

        t->t_next    = _tags.t_next;
        _tags.t_next = t;

        return t->t_id;
}

void *smalloc(tag_t tid, size_t sz)
{       
        struct tag *t = _tags.t_next;
        void *p;

        while (t) {
                if (t->t_id == tid)                                                                          
                        break;

                t = t->t_next;
        }

        if (!t) 
                return NULL;

        if (((unsigned long) t->t_p - (unsigned long) t->t_buf + sz)
            > t->t_len)
                return NULL;

        p = t->t_p;

        t->t_p += sz;

        return p;
}

void sc_mem_add(sc_t *sc, tag_t tid, int prot)
{
        unsigned long *p = sc->sc_mem;
        unsigned long addr;
        struct tag *t = _tags.t_next;

        while (t) {
                if (t->t_id == tid)
                        break;

                t = t->t_next;
        }

        if (!t)
                errx(0, "sc_mem_add()");

        while (*p)
                p++;

        if (((unsigned long) p - (unsigned long) sc->sc_mem)
            >= sizeof(sc->sc_mem))
                errx(1, "sc_mem_add()");

        addr = ((unsigned long) t->t_buf & 0xfffffffffffffff0L);
        assert(addr == (unsigned long) t->t_buf);
        assert((prot & 0xf) == prot);

        *p = addr | prot;
}

void sc_fd_add(sc_t *sc, int fd, int prot)
{
	unsigned long *f = sc->sc_fd;

	while (*f)
		f++;

	if (((unsigned long) f - (unsigned long) sc->sc_fd)
	    >= sizeof(sc->sc_fd))
		errx(1, "sc_fd_add()");

	*f = (fd << 8) | prot;

	assert((*f >> 8) == fd);
	assert((*f & 0xf) == prot);
}

void sc_sys_add(sc_t *sc, int sysno)
{
	int pos = sysno / 8;

	if (pos < 0 || pos > (sizeof(sc->sc_sys) / sizeof(*sc->sc_sys)))
		errx(1, "sc_sys_add");

	sc->sc_sys[pos] |= 1 << (sysno % 8);
}
