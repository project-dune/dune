/**
 * dune.h - public header for Dune support
 */

#include <linux/types.h>

/*
 * IOCTL interface
 */

/* FIXME: this must be reserved in miscdevice.h */
#define DUNE_MINOR       233

#define DUNE_ENTER	_IOR(DUNE_MINOR, 0x01, struct dune_config)
#define DUNE_GET_SYSCALL	 _IO(DUNE_MINOR, 0x02)
#define DUNE_GET_LAYOUT	_IOW(DUNE_MINOR, 0x03, struct dune_layout)

// XXX: Must match libdune/dune.h
#define DUNE_SIGNAL_INTR_BASE 200

struct dune_config {
	__u64 rip;
	__u64 rsp;
	__u64 cr3;
	__s64 ret;
} __attribute__((packed));

struct dune_layout {
	__u64 base_proc;
	__u64 base_map;
	__u64 base_stack;
} __attribute__((packed));

#define GPA_SIZE ((unsigned long) 1 << 34)
#define GPA_MASK (GPA_SIZE - 1)
#define LG_ALIGN(addr)	((addr + (1 << 21) - 1) & ~((1 << 21) - 1))

enum {
	GPA_ADDR_PROC	= 0x000000000,
	GPA_ADDR_MAP 	= 0x400000000,
	GPA_ADDR_STACK	= 0x800000000,
	GPA_ADDR_INVAL	= 0xC00000000,
};
