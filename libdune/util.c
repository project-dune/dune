/*
 * util.c - this file is for random utilities and hypervisor backdoors
 */

#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <signal.h>

#include "dune.h"
#include "../kern/dune.h"

static int dune_puts(const char *buf)
{
	long ret;

	asm volatile("movq $1, %%rax \n\t" // SYS_write
	    "movq $1, %%rdi \n\t" // STDOUT
	    "movq %1, %%rsi \n\t" // string
	    "movq %2, %%rdx \n\t" // string len
	    "vmcall \n\t"
	    "movq %%rax, %0 \n\t" :
	    "=r" (ret) : "r" (buf), "r" (strlen(buf)) :
	    "rax", "rdi", "rsi", "rdx");

	return ret;
}

/**
 * dune_printf - a raw low-level printf request that uses a hypercall directly
 * 
 * This is intended for working around libc syscall issues.
 */
int dune_printf(const char *fmt, ...)
{
	va_list args;
	char buf[1024];

	va_start(args, fmt);

	vsprintf(buf, fmt, args);

	return dune_puts(buf);
}

void * dune_mmap(void *addr, size_t length, int prot,
	     int flags, int fd, off_t offset)
{
	void *ret_addr;

	asm volatile("movq $9, %%rax \n\t" // SYS_mmap
	    "movq %1, %%rdi \n\t"
	    "movq %2, %%rsi \n\t"
	    "movl %3, %%edx \n\t"
	    "movq %4, %%r10 \n\t"
	    "movq %5, %%r8 \n\t"
	    "movq %6, %%r9 \n\t"
	    "vmcall \n\t"
	    "movq %%rax, %0 \n\t" :
	    "=r" ((unsigned long) ret_addr) : "r" ((unsigned long) addr), "r" (length),
	    "r" (prot), "r" ((unsigned long) flags), "r" ((unsigned long) fd),
	    "r" ((unsigned long) offset) : "rax", "rdi", "rsi", "rdx");

	return ret_addr;
}

/**
 * dune_die - kills the Dune process immediately
 *
 */
void dune_die(void)
{
	asm volatile("movq $60, %rax\n" // exit
		     "vmcall\n");
}

/**
 * dune_passthrough_syscall - makes a syscall using the args of a trap frame
 *
 * @tf: the trap frame to apply
 * 
 * sets the return code in tf->rax
 */
void dune_passthrough_syscall(struct dune_tf *tf)
{
	asm volatile("movq %2, %%rdi \n\t"
		     "movq %3, %%rsi \n\t"
		     "movq %4, %%rdx \n\t"
		     "movq %5, %%r10 \n\t"
		     "movq %6, %%r8 \n\t"
		     "movq %7, %%r9 \n\t"
		     "vmcall \n\t"
		     "movq %%rax, %0 \n\t" :
		     "=a" (tf->rax) :
		     "a" (tf->rax), "r" (tf->rdi), "r" (tf->rsi),
		     "r" (tf->rdx), "r" (tf->rcx), "r" (tf->r8),
		     "r" (tf->r9) : "rdi", "rsi", "rdx", "r10",
		     "r8", "r9", "memory");     
}

sighandler_t dune_signal(int sig, sighandler_t cb)
{
	dune_intr_cb x = (dune_intr_cb) cb; /* XXX */

	if (signal(sig, cb) == SIG_ERR)
		return SIG_ERR;

	dune_register_intr_handler(DUNE_SIGNAL_INTR_BASE + sig, x);

	return NULL;
}
