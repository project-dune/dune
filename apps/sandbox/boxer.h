#ifndef __BOXER_H__
#define __BOXER_H__

typedef int (*boxer_syscall_cb)(struct dune_tf *tf);

extern void boxer_register_syscall_monitor(boxer_syscall_cb cb);
extern int boxer_main(int argc, char *argv[]);

#endif /* __BOXER_H__ */
