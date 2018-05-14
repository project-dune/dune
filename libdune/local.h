/*
 * local.h - internal definitions
 */


// standard definitions
#define __str_t(x...)	#x
#define __str(x...)	__str_t(x)
extern int arch_prctl(int code, unsigned long *addr);

// assembly routines from dune.S
extern int __dune_enter(int fd, struct dune_config *config);
extern int __dune_ret(void);
extern void __dune_syscall(void);
extern void __dune_syscall_end(void);
extern void __dune_intr(void);
extern void __dune_go_linux(struct dune_config *config);
extern void __dune_go_dune(int fd, struct dune_config *config);

// assembly routine for handling vsyscalls
extern char __dune_vsyscall_page;

// initialization
extern int dune_page_init(void);
void setup_apic(void);
void apic_init_rt_entry(void);
