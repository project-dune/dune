#ifndef __STHREAD_H__
#define __STHREAD_H__

typedef struct sc {
        unsigned long   sc_mem[8];
	unsigned long	sc_fd[8];
	unsigned char	sc_sys[16];
} sc_t;

typedef int sthread_t;
typedef int tag_t;

typedef void *(*stcb_t)(void*);

extern void sc_init(sc_t *);
extern void sc_mem_add(sc_t *sc, tag_t t, int prot);
extern void sc_fd_add(sc_t *sc, int fd, int prot);
extern void sc_sys_add(sc_t *sc, int sysno);

extern int sthread_init(void);
extern int sthread_create(sthread_t *, sc_t *sc, stcb_t cb, void *arg);
extern int sthread_join(sthread_t, void **ret);

extern tag_t tag_new(void);
extern void *smalloc(tag_t t, size_t);

#endif /* __STHREAD_H__ */
