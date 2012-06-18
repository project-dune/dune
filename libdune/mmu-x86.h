#ifndef JOS_MACHINE_MMU_X86_H
#define JOS_MACHINE_MMU_X86_H

/*
 *
 * Part 1.  Paging data structures and control registers
 *
 */

/* index into:         
 *   n = 0 => page table 
 *   n = 1 => page directory
 *   n = 2 => page directory pointer
 *   n = 3 => page map level 4
 */
#define PDXMASK		((1 << NPTBITS) - 1)
#define PDSHIFT(n)	(12 + NPTBITS * (n))
#define PDX(n, la)	((((uintptr_t) (la)) >> PDSHIFT(n)) & PDXMASK)

#define NPTENTRIES	(1 << NPTBITS)

/* page number field of address */
#define PPN(la)		((la) >> PGSHIFT)

/* page size */
#define PGSHIFT		12		/* log2(PGSIZE) */
#define PGSIZE		(1 << PGSHIFT)	/* bytes mapped by a page */
#define PGMASK		(PGSIZE - 1)

/* offset in page */
#define PGOFF(la)	(((uintptr_t) (la)) & PGMASK)
#define PGADDR(la)	(((uintptr_t) (la)) & ~CAST64(PGMASK))

/* big page size */
#define BIG_PGSHIFT	21
#define BIG_PGSIZE	(1 << BIG_PGSHIFT)
#define BIG_PGMASK	(BIG_PGSIZE - 1)

/* offset in big page */
#define BIG_PGOFF(la)	(((uintptr_t) (la)) & BIG_PGMASK)
#define BIG_PGADDR(la)	(((uintptr_t) (la)) & ~CAST64(BIG_PGMASK))

/* Page table/directory entry flags. */
#define PTE_P		0x0001		/* Present */
#define PTE_W		0x0002		/* Writeable */
#define PTE_U		0x0004		/* User */
#define PTE_PWT		0x0008		/* Write-Through */
#define PTE_PCD		0x0010		/* Cache-Disable */
#define PTE_A		0x0020		/* Accessed */
#define PTE_D		0x0040		/* Dirty */
#define PTE_PS		0x0080		/* Page size, in PD/PDP/PML4 */
#define PTE_PAT		0x0080		/* Page attribute table, in 4KB PTE */
#define PTE_G		0x0100		/* Global */
#define PTE_AVAIL	0x0E00		/* 3 bits not used by hardware */
#define PTE_PAT_PS	0x1000		/* Page attribute table, in 2MB PTE */
#define PTE_AVAIL2	UINT64(0x7FF0000000000000) /* 11 bits not used by hardware */
#define PTE_NX		UINT64(0x8000000000000000) /* No execute */

/* DUNE Specific Flags - Using available bits in PTE */
#define PTE_COW		0x0200		/* Copy-on-write - must also be read-only */
#define PTE_USR1	UINT64(0x4000000000000000) /* Reserved for user software */
#define PTE_USR2	UINT64(0x2000000000000000) /* Reserved for user software */
#define PTE_USR3	UINT64(0x1000000000000000) /* Reserved for user software */

/* address in page table entry */
#define PTE_ADDR(pte) ((physaddr_t) (pte) & UINT64(0xffffffffff000))
#define PTE_FLAGS(pte) ((physaddr_t) (pte) & UINT64(0xfff0000000000fff))

/* Control Register flags */
#define CR0_PE 0x1		/* Protected mode enable */
#define CR0_MP 0x2		/* Monitor coProcessor */
#define CR0_EM 0x4		/* Emulation */
#define CR0_TS 0x8		/* Task Switched */
#define CR0_ET 0x10		/* Extension Type */
#define CR0_NE 0x20		/* Numeric Errror */
#define CR0_WP 0x10000		/* Write Protect */
#define CR0_AM 0x40000		/* Alignment Mask */
#define CR0_NW 0x20000000	/* Not Writethrough */
#define CR0_CD 0x40000000	/* Cache Disable */
#define CR0_PG 0x80000000	/* Paging */

#define CR3_PWT 0x8		/* Page-level writethrough */
#define CR3_PCD 0x10		/* Page-level cache disable */

#define CR4_VME 0x1		/* V86 Mode Extensions */
#define CR4_PVI 0x2		/* Protected-Mode Virtual Interrupts */
#define CR4_TSD 0x4		/* Time Stamp Disable */
#define CR4_DE 0x8		/* Debugging Extensions */
#define CR4_PSE 0x10		/* Page Size Extensions */
#define CR4_PAE 0x20		/* Page address extension */
#define CR4_MCE 0x40		/* Machine Check Enable */
#define CR4_PGE 0x80		/* Page-global enable */
#define CR4_PCE 0x100		/* Performance counter enable */
#define CR4_OSFXSR 0x200	/* FXSAVE/FXRSTOR support */
#define CR4_OSX 0x400		/* OS unmasked exception support */

/* MTRR registers */
#define MTRR_CAP 0xfe		/* MTRR capabilities */
#define MTRR_CAP_VCNT_MASK 0xff	/* Variable-size register count */
#define MTRR_CAP_FIX 0x100	/* Fixed-size register support */
#define MTRR_CAP_WC 0x400	/* Write-combining support */
#define MTRR_BASE(i) (0x200 + 2*(i))	/* Physical address base */
#define MTRR_BASE_UC 0x00	/* Uncacheable */
#define MTRR_BASE_WC 0x01	/* Write-Combining */
#define MTRR_BASE_WT 0x04	/* Writethrough */
#define MTRR_BASE_WP 0x05	/* Write-Protect */
#define MTRR_BASE_WB 0x06	/* Writeback */
#define MTRR_MASK(i) (0x201 + 2*(i))	/* Physical address mask */
#define MTRR_MASK_FULL PGADDR((ONE << 36) - 1)
#define MTRR_MASK_VALID 0x800

/* EFER Register */
#define EFER 0xc0000080		/* MSR number */
#define EFER_SCE 0x1		/* System-call extension */
#define EFER_LME 0x100		/* Long mode enable */
#define EFER_LMA 0x400		/* Long mode active */
#define EFER_NXE 0x800		/* No-execute enable */
#define EFER_FFXSR 0x4000	/* Fast FXSAVE/FXRSTOR */

/* FS/GS base registers */
#define MSR_FS_BASE	0xc0000100
#define MSR_GS_BASE	0xc0000101

/* Debug registers */
#define MSR_DEBUG_CTL	0x1d9		/* MSR number */
#define DEBUG_CTL_LBR	(1 << 0)	/* Last-Branch Record */

#define MSR_LBR_FROM_IP	0x1db		/* Last branch from IP */
#define MSR_LBR_TO_IP	0x1dc		/* Last branch to IP */
#define MSR_LEX_FROM_IP	0x1dd		/* Last exception from IP */
#define MSR_LEX_TO_IP	0x1de		/* Last exception to IP */

#define DR7_L(n)	(ONE << ((n)*2)) /* Local breakpoint enable */
#define DR7_G(n)	(ONE << ((n)*2+1)) /* Global breakpoint enable */
#define DR7_LE		(ONE << 8)	/* Local enable */
#define DR7_GE		(ONE << 9)	/* Global enable */
#define DR7_GD		(ONE << 13)	/* General-detect enable */
#define DR7_RW_SHIFT(n)	((n) * 4 + 16)	/* Breakpoint access mode */
#define DR7_LEN_SHIFT(n) ((n) * 4 + 18)	/* Breakpoint addr length */

#define DR7_RW_EXEC	0x0
#define DR7_RW_WRITE	0x1
#define DR7_RW_IO	0x2
#define DR7_RW_RW	0x3

#define DR7_LEN_1	0x0
#define DR7_LEN_2	0x1
#define DR7_LEN_8	0x2
#define DR7_LEN_4	0x3

/* Rflags register */
#define FL_CF 0x00000001	/* Carry Flag */
#define FL_PF 0x00000004	/* Parity Flag */
#define FL_AF 0x00000010	/* Auxiliary carry Flag */
#define FL_ZF 0x00000040	/* Zero Flag */
#define FL_SF 0x00000080	/* Sign Flag */
#define FL_TF 0x00000100	/* Trap Flag */
#define FL_IF 0x00000200	/* Interrupt Flag */
#define FL_DF 0x00000400	/* Direction Flag */
#define FL_OF 0x00000800	/* Overflow Flag */
#define FL_IOPL_MASK 0x00003000 /* I/O Privilege Level bitmask */
#define FL_IOPL_0 0x00000000	/*   IOPL == 0 */
#define FL_IOPL_1 0x00001000	/*   IOPL == 1 */
#define FL_IOPL_2 0x00002000	/*   IOPL == 2 */
#define FL_IOPL_3 0x00003000	/*   IOPL == 3 */
#define FL_NT 0x00004000	/* Nested Task */
#define FL_RF 0x00010000	/* Resume Flag */
#define FL_VM 0x00020000	/* Virtual 8086 mode */
#define FL_AC 0x00040000	/* Alignment Check */
#define FL_VIF 0x00080000	/* Virtual Interrupt Flag */
#define FL_VIP 0x00100000	/* Virtual Interrupt Pending */
#define FL_ID 0x00200000	/* ID flag */

/* Page fault error codes */
#define FEC_P 0x1	    /* Fault caused by protection violation */
#define FEC_W 0x2		/* Fault caused by a write */
#define FEC_U 0x4		/* Fault occured in user mode */
#define FEC_RSV 0x8		/* Fault caused by reserved PTE bit */
#define FEC_I 0x10		/* Fault caused by instruction fetch */

/*
 *
 * Part 2.  Segmentation data structures and constants.
 *
 */

/* STA_ macros are for segment type values */
#define STA_A (ONE << 0)	/* Accessed */
#define STA_W (ONE << 1)	/* Writable (for data segments) */
#define STA_E (ONE << 2)	/* Expand down (for data segments) */
#define STA_X (ONE << 3)	/* 1 = Code segment (executable) */
#define STA_R (ONE << 1)	/* Readable (for code segments) */
#define STA_C (ONE << 2)	/* Conforming (for code segments) */

/* SEG_ macros specify segment type values shifted into place */
#define SEG_A (STA_A << 40)	/* Accessed */
#define SEG_W (STA_W << 40)	/* Writable (for data segments) */
#define SEG_E (STA_E << 40)	/* Expand down (for data segments) */
#define SEG_X (STA_X << 40)	/* 1 = Code segment (executable) */
#define SEG_R (STA_R << 40)	/* Readable (for code segments) */
#define SEG_C (STA_C << 40)	/* Conforming (for code segments) */

#define SEG_S (ONE << 44)	/* 1 = non-system, 0 = system segment */

#define SEG_LDT (UINT64 (0x2) << 40) /* 64-bit local descriptor segment */
#define SEG_TSSA (UINT64 (0x9) << 40) /* Available 64-bit TSS */
#define SEG_TSSB (UINT64 (0xa) << 40) /* Busy 64-bit TSS */
#define SEG_CG (UINT64 (0xc) << 40) /* 64-bit Call Gate */
#define SEG_IG (UINT64 (0xe) << 40) /* 64-bit Interrupt Gate */
#define SEG_TG (UINT64 (0xf) << 40) /* 64-bit Trap Gate */

#define SEG_DPL(x) (((x) & UINT64(3)) << 45) /* Descriptor privilege level */
#define SEG_P (ONE << 47)	/* Present */
#define SEG_L (ONE << 53)	/* Long mode */
#define SEG_D (ONE << 54)	/* 1 = 32-bit in legacy, 0 in long mode */
#define SEG_G (ONE << 55)	/* Granulatity: 1 = scale limit by 4K */

/* Base and limit for 32-bit or low half of 64-bit segments */
#define SEG_LIM(x) (((x) & 0xffff) | ((x) & UINT64 (0xf0000)) << 32)
#define SEG_BASELO(x) (((CAST64 (x) & 0xffffff) << 16)		\
		       | ((CAST64 (x) & 0xff000000) << 32))
#define SEG_BASEHI(x) (CAST64 (x) >> 32)

#define SEG32_ASM(type, base, lim)					\
    .word (((lim) >> 12) & 0xffff), ((base) & 0xffff);			\
    .byte (((base) >> 16) & 0xff), (0x90 | (type)),			\
	  (0xC0 | (((lim) >> 28) & 0xf)), (((base) >> 24) & 0xff)

#define SEG32(type, base, lim, dpl)					\
  ((type) | SEG_S | SEG_P | SEG_D | SEG_G | SEG_A | SEG_DPL (dpl)	\
   | SEG_BASELO (base) | SEG_LIM ((lim) >> 12))

#define SEG64(type, dpl)						\
  ((type) | SEG_S | SEG_P | SEG_G | SEG_L | SEG_A | SEG_DPL (dpl)		\
   | SEG_LIM (0xffffffff))

/* Target and segment selector for trap/interrupt gates */
#define SEG_SEL(x) (((x) & 0xffff) << 16)
#define SEG_TARGETLO(x) ((CAST64 (x) & 0xffff)			\
			 | ((CAST64 (x) & 0xffff0000) << 32))
#define SEG_TARGETHI(x) (CAST64 (x) >> 32)

#define GATE32(type, sel, target, dpl)					   \
  ((type) | SEG_DPL (dpl) | SEG_P | SEG_SEL (sel) | SEG_TARGETLO (target))
#define SETGATE(gate, type, sel, target, dpl)		\
  do {							\
    gate.gd_lo = GATE32 (type, sel, target, dpl);	\
    gate.gd_hi = SEG_TARGETHI (target);			\
  } while (0)

#ifndef __ASSEMBLER__

struct Fpregs {
    uint16_t cwd;
    uint16_t swd;
    uint16_t twd;
    uint16_t fop;
    uint64_t rip;
    uint64_t rdp;
    uint32_t mxcsr;
    uint32_t mxcsr_mask;
    uint32_t st_space[32];   /* 8*16 bytes for each FP-reg = 128 bytes */
    uint32_t xmm_space[64];  /* 16*16 bytes for each XMM-reg = 128 bytes */
    uint32_t padding[24];
};

#endif /* !__ASSEMBLER__ */

#endif /* !JOS_MACHINE_MMU_X86_H */
