#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>
#include <err.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/mman.h>

#include <dune.h>
#include "sthread.h"

#define NR_REP	100

typedef void (*cb_t)(void);

static int _use_vmcall_gettimeofday;

static unsigned char *_crap;
static unsigned char *_crap2;
static unsigned char *_crappy;
static ptent_t *_pg1, *_pg2;
static int _pages;

static int usm_gettimeofday(struct timeval *tp, void *tzp)
{       
        int ret;
       
	if (!_use_vmcall_gettimeofday)
		return gettimeofday(tp, tzp);
 
        asm("vmcall\n" : "=a" (ret)
                       : "a" (SYS_gettimeofday), "D" (tp), "S" (tzp));

        return ret;
}

static int benchmark_latency(cb_t cb)
{       
        int i;
        struct timeval a, b;
        unsigned long t;
        unsigned long avg = 0;
        int num = 0;
	int av;
            
        for (i = 0; i < 10; i++) {
		usm_gettimeofday(&a, NULL);
                cb();
		usm_gettimeofday(&b, NULL);
                
                t = b.tv_sec - a.tv_sec;
                
                if (t == 0)
                        t = b.tv_usec - a.tv_usec;
                else {                                                                                        
                        t--;                                                                                  
                                                                                                              
                        t *= 1000 * 1000;

                        t += b.tv_usec;
                        t += 1000 * 1000 - a.tv_usec;
                }

                printf("Elapsed %luus\n", t);

                if (i > 4) {
                        avg += t;
                        num++;
                }
        }

	/* XXX roundf */
	av = (int) ((double) avg / (double) num);

        printf("Avg %d (%d samples)\n", av, num);

	return av;
}

static void *thread(void* a)
{
//	printf("In thread\n");

	return NULL;
}

static void fork_bench(void)
{
	int pid;

	pid = fork();
	if (pid == -1)
		err(1, "fork()");

	if (pid == 0) {
		thread(NULL);
		exit(0);
	} else {
		wait(NULL);
	}
}

static void pthread_bench(void)
{
	pthread_t pt;

	if (pthread_create(&pt, NULL, thread, NULL) != 0)
		err(1, "pthread_create()");

	if (pthread_join(pt, NULL) != 0)
		err(1, "pthread_join()");
}

static void sthread_bench(void)
{
	sthread_t st;
	sc_t sc;

	sc_init(&sc);

	if (sthread_create(&st, &sc, thread, NULL) != 0)
		err(1, "sthread_create()");

	if (sthread_join(st, NULL) != 0)
		err(1, "sthread_join()");
}

static void http_bench(void)
{
	int s;
	struct sockaddr_in s_in;
	char buf[1024];
	char *ip = getenv("BENCH_IP");

	if ((s = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1)
		err(1, "socket()");

	memset(&s_in, 0, sizeof(s_in));
	s_in.sin_family      = PF_INET;
	s_in.sin_port        = htons(80);
	s_in.sin_addr.s_addr = inet_addr(ip ? ip : "127.0.0.1");

	if (connect(s, (struct sockaddr*) &s_in, sizeof(s_in)) == -1)
		err(1, "connect()");

	snprintf(buf, sizeof(buf), "GET / HTTP/1.0\r\n\r\n");

	if (write(s, buf, strlen(buf)) != strlen(buf))
		err(1, "write()");

	if (read(s, buf, sizeof(buf)) <= 0)
		err(1, "read()");

	close(s);
}

static void bench_http(void)
{
	benchmark_latency(http_bench);
}

static void bench_sthreads(void)
{
	int pid = fork();

	if (pid == 0) {
		printf("fork\n");
		benchmark_latency(fork_bench);

		printf("pthread\n");
		benchmark_latency(pthread_bench);
		exit(0);
	} else
		wait(NULL);

	printf("sthread\n");
	_use_vmcall_gettimeofday = 1;

	if (sthread_init() == -1)
		err(1, "sthread_init()");

	benchmark_latency(sthread_bench);
}

static void set_assert(unsigned char *crap, unsigned char old, unsigned char new)
{
//	printf("Crap [%p] is %u want %u setting %u\n", crap, *crap, old, new);

	assert(*crap == old);

	*crap = new;
}

static int setup_mem_cb(const void *arg, ptent_t *pte, void *va)
{
	printf("PTE %lx addr %lx\n", *pte, PTE_ADDR(*pte));

	*pte = (PTE_ADDR(*pte) + 4096) | PTE_P | PTE_W | PTE_U;

	printf("PTE now %lx\n", *pte);

	return 0;
}

static void setup_mem(void)
{
	_pg1 = pgroot; 

	_pg2 = dune_vm_clone(_pg1);

	dune_vm_page_walk(_pg1, _crap, _crap, setup_mem_cb, NULL);

}

static void no_switch(void)
{
	int i;

	for (i = 0; i < NR_REP; i++) {
		*_crap = 0;

		set_assert(_crap, 0, 1);
		set_assert(_crap, 1, 2);

		set_assert(_crap, 2, 3);
		set_assert(_crap, 3, 4);

		set_assert(_crap, 4, 5);
		set_assert(_crap, 5, 6);
	}
}

static void with_switch(void)
{
	int i;

	for (i = 0; i < NR_REP; i++) {
		load_cr3((unsigned long) _pg2);
		*_crap2 = 0;
		set_assert(_crap2, 0, 1);
		set_assert(_crap2, 1, 2);

		load_cr3((unsigned long) _pg1);
		set_assert(_crap, 2, 3);
		set_assert(_crap, 3, 4);

		load_cr3((unsigned long) _pg2);
		set_assert(_crap2, 4, 5);
		set_assert(_crap2, 5, 6);
	}
}

static void with_switch_no_flush(void)
{
	int i;

	for (i = 0; i < NR_REP; i++) {
		load_cr3((unsigned long) _pg2 | 1UL | CR3_NOFLUSH);
		*_crap2 = 0;
		set_assert(_crap2, 0, 1);
		set_assert(_crap2, 1, 2);

		load_cr3((unsigned long) _pg1 | 0UL | CR3_NOFLUSH);
		set_assert(_crap, 2, 3);
		set_assert(_crap, 3, 4);

		load_cr3((unsigned long) _pg2 | 1UL | CR3_NOFLUSH);
		set_assert(_crap2, 4, 5);
		set_assert(_crap2, 5, 6);
	}
}

static void ctx_switch(void)
{
	load_cr3((unsigned long) _pg2);
	set_assert(_crap2, 0, 1);
	set_assert(_crap2, 1, 2);

	load_cr3((unsigned long) _pg1);
	set_assert(_crap, 2, 3);
	set_assert(_crap, 3, 4);

	load_cr3((unsigned long) _pg2);
	set_assert(_crap2, 4, 5);
	set_assert(_crap2, 5, 6);
}

static void syscall_handler(struct dune_tf *tf)
{
        int syscall_num = (int) tf->rax;

	printf("Got syscall %d\n", syscall_num);

	dune_passthrough_syscall(tf);
}

static void do_pages(int p)
{
	int i, j;

	for (i = 0; i < NR_REP; i++) {
		if (p == 0) {
		} else if (p == 1) {
			load_cr3((unsigned long) _pg2);
		} else
			load_cr3((unsigned long) _pg2 | 1UL | CR3_NOFLUSH);

		for (j = 0; j < _pages; j++)
			_crappy[j * 4096] = 0x69;

		if (p == 0) {
		} else if (p == 1) {
			load_cr3((unsigned long) _pg1);
		} else
			load_cr3((unsigned long) _pg1 | 0UL | CR3_NOFLUSH);

		for (j = 0; j < _pages; j++)
			_crappy[j * 4096] = 0x69;
	}
}

static void no_switch_pages(void)
{
	do_pages(0);
}

static void switch_pages(void)
{
	do_pages(1);
}

static void no_flush_switch_pages(void)
{
	do_pages(2);
}

static void pwn_pages(int pages)
{
	int a[3];

	printf("Alright kids - pwning %d pages\n", pages);

	_pages = pages;

	_crappy = mmap(NULL, 4096 * pages, PROT_READ | PROT_WRITE,
		       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (_crappy == MAP_FAILED)
		err(1, "mmap()");

	memset(_crappy, 0, 4096 * pages);

	a[0] = benchmark_latency(no_switch_pages);
	a[1] = benchmark_latency(switch_pages);
	a[2] = benchmark_latency(no_flush_switch_pages);

	printf("\n=============\n");
	printf("result %d %d %d %d\n", pages, a[0], a[1], a[2]);
}

static void bench_switch(int pages, int pages_end)
{
	printf("w00t\n");

	_crap = mmap(NULL, 4096 * 2, PROT_READ | PROT_WRITE,
		     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	if (_crap == MAP_FAILED)
		err(1, "mmap()");

	_crap2 = _crap + 4096;

	printf("Crap %p crap2 %p\n", _crap, _crap2);

	if (dune_init_and_enter())
		errx(1, "dune_init_and_enter()");

	_use_vmcall_gettimeofday = 1;

        dune_register_syscall_handler(syscall_handler);

	setup_mem();

	ctx_switch();

	printf("still alive\n");

	printf("No switch\n");
	benchmark_latency(no_switch);

	printf("With switch\n");
	benchmark_latency(with_switch);

	printf("With switch no flush\n");
	benchmark_latency(with_switch_no_flush);

	if (pages) {
		if (!pages_end)
			pages_end = pages;

		for (; pages <= pages_end; pages++)
			pwn_pages(pages);
	}

	printf("Still ballin\n");
}

int main(int argc, char *argv[])
{
	int bench = 0;

	printf("w00t\n");

	if (argc > 1)
		bench = atoi(argv[1]);

	switch (bench) {
	case 0:
		bench_sthreads();
		break;

	case 1:
		bench_http();
		break;

	case 2:
		bench_switch(atoi(argv[2]), atoi(argv[3]));
		break;
	}

	printf("all done\n");

	exit(0);
}
