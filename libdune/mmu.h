#ifndef JOS_MACHINE_MMU_H
#define JOS_MACHINE_MMU_H

# define UINT64(x) ((uint64_t) x)
# define CAST64(x) ((uint64_t) x)
#define ONE UINT64 (1)

#include "types.h"
#include "mmu-x86.h"

typedef uint64_t ptent_t;

/*
 * AMD64-specific bits
 */

/* Page directory and page table constants. */
#define NPTBITS	    9		/* log2(NPTENTRIES) */
#define NPTLVLS	    3		/* page table depth -1 */
#define PD_SKIP	    6		/* Offset of pd_lim in Pseudodesc */

#ifndef __ASSEMBLER__
/* Pseudo-descriptors used for LGDT, LLDT and LIDT instructions. */
struct Pseudodesc {
  uint16_t pd__garbage1;
  uint16_t pd__garbage2;
  uint16_t pd__garbage3;
  uint16_t pd_lim;		/* Limit */
  uint64_t pd_base;		/* Base address */
} __attribute__((packed));

struct Tss {
  char tss__ign1[4];
  uint64_t tss_rsp[3];		/* Stack pointer for CPL 0, 1, 2 */
  uint64_t tss_ist[8];		/* Note: tss_ist[0] is ignored */
  char tss__ign2[10];
  uint16_t tss_iomb;		/* I/O map base */
  uint8_t tss_iopb[];
} __attribute__ ((packed));

struct Gatedesc {
  uint64_t gd_lo;
  uint64_t gd_hi;
};

struct Trapframe_aux {
};

struct Trapframe {
  /* callee-saved registers except %rax and %rsi */
  uint64_t tf_rcx;
  uint64_t tf_rdx;
  uint64_t tf_rdi;
  uint64_t tf_r8;
  uint64_t tf_r9;
  uint64_t tf_r10;
  uint64_t tf_r11;

  /* caller-saved registers */
  uint64_t tf_rbx;
  uint64_t tf_rbp;
  uint64_t tf_r12;
  uint64_t tf_r13;
  uint64_t tf_r14;
  uint64_t tf_r15;

  /* for use by trap_{ec,noec}_entry_stub */
  union {
    uint64_t tf_rsi;
    uint64_t tf__trapentry_rip;
  };

  /* saved by trap_{ec,noec}_entry_stub */
  uint64_t tf_rax;

  /* hardware-saved registers */
  uint32_t tf_err;
  uint32_t tf__pad1;
  uint64_t tf_rip;
  uint16_t tf_cs;
  uint16_t tf_ds;	// not saved/restored by hardware
  uint16_t tf_es;	// not saved/restored by hardware
  uint16_t tf_fs;	// not saved/restored by hardware
  uint64_t tf_rflags;
  uint64_t tf_rsp;
  uint16_t tf_ss;
  uint16_t tf_gs;	// not saved/restored by hardware
  uint16_t tf__pad3[2];
};
#endif

#endif /* !JOS_MACHINE_MMU_H */
