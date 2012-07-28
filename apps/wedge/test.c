#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <assert.h>
#include <sys/syscall.h>
#include <fcntl.h>

#include "sthread.h"

static int _global = 1;

static void *sthread_cb(void *arg)
{
	if (arg != (void*) 0x666)
		errx(1, "arg %p", arg);

	return (void*) 0x69;
}

static void *launch_sthread(stcb_t cb, void *arg)
{
	sc_t sc;
	sthread_t st;
	void *ret;

	sc_init(&sc);

	if (sthread_create(&st, &sc, cb, arg))
		err(1, "sthread_create()");

	if (sthread_join(st, &ret))
		err(1, "sthread_join()");

	return ret;
}

static void test_sthread(void)
{
	void *ret = launch_sthread(sthread_cb, (void*) 0x666);

	if (ret != (void*) 0x69)
		errx(1, "ret %p", ret);
}

static void *sthread_global(void *arg)
{
	if (_global != 1)
		errx(1, "global in sthread %d\n", _global);

	_global = 3;

	return NULL;
}

static void test_global(void)
{
	launch_sthread(sthread_global, NULL);
}

static void *sthread_stack(void *arg)
{
	unsigned char stack[1024];


	if (stack[69] != 0)
		errx(1, "stack is %x\n", stack[69]);

	stack[69] = 0x69;

	return NULL;
}

static void test_stack(void)
{
	launch_sthread(sthread_stack, NULL);
}

static void *smalloc_st(void *arg)
{
	char *crap = arg;

	if (strcmp(crap, "hi") != 0)
		errx(1, "crap is %s", crap);

	strcpy(crap, "bye");

	return NULL;
}

static void test_smalloc(void)
{
	tag_t t = tag_new();
	char *crap;
	sc_t sc;
	sthread_t st;

	crap = smalloc(t, 1024);
	strcpy(crap, "hi");

	sc_init(&sc);
	sc_mem_add(&sc, t, PROT_READ | PROT_WRITE);

	if (sthread_create(&st, &sc, smalloc_st, crap))
		err(1, "sthread_create()");

	if (sthread_join(st, NULL))
		err(1, "sthread_join()");

	if (strcmp(crap, "bye") != 0)
		errx(1, "master crap is %s", crap);
}

static void *fd_st(void *arg)
{
	int fd = (int) (long) arg;

	if (write(fd, "bye", 3) != 3)
		err(1, "write()");

	return NULL;
}

static void test_fd(void)
{
	int p[2];
	sc_t sc;
	char buf[1024];
	int rc;
	sthread_t st;

	if (pipe(p) == -1)
		err(1, "pipe()");

	sc_init(&sc);
	sc_fd_add(&sc, p[1], PROT_WRITE);

	if (sthread_create(&st, &sc, fd_st, (void*) (long) p[1]))
		err(1, "sthread_create()");

	if (sthread_join(st, NULL))
		err(1, "sthread_join()");

	rc = read(p[0], buf, sizeof(buf) - 1);
	if (rc <= 0)
		err(1, "read()");

	buf[rc] = 0;

	if (strcmp(buf, "bye") != 0)
		errx(1, "buf is %s", buf);

	close(p[0]);
	close(p[1]);
}

static void *sys_st(void *arg)
{
	char *buf = arg;
	int fd;
	int rc;

	fd = open("/etc/passwd", O_RDONLY);
	if (fd == -1)
		err(1, "open()");

	rc = read(fd, buf, 1023);
	if (rc <= 0)
		err(1, "read()");

	buf[rc] = 0;

	close(fd);

	return NULL;
}

static void test_syscall(void)
{
	sc_t sc;
	tag_t t;
	char *buf;
	sthread_t st;

	t = tag_new();
	buf = smalloc(t, 1024);
	assert(buf);

	sc_init(&sc);
	sc_mem_add(&sc, t, PROT_READ | PROT_WRITE);
	sc_sys_add(&sc, SYS_open);
	sc_sys_add(&sc, SYS_close);

	if (sthread_create(&st, &sc, sys_st, buf))
		err(1, "sthread_create()");

	if (sthread_join(st, NULL))
		err(1, "sthread_join()");

	if (strncmp(buf, "root", 4) != 0)
		errx(1, "buf is %s", buf);
}

int main(int argc, char *argv[])
{
	printf("==== start\n");

	if (sthread_init())
		err(1, "sthread_init()");

	printf("==== Basic sthread\n");
	test_sthread();
	test_sthread();

	printf("==== Globals\n");
	_global = 2;
	test_global();
	if (_global != 2)
		errx(1, "global in master %d\n", _global);
	test_global();

	printf("==== Stack\n");
	test_stack();
	test_stack();

	printf("==== smalloc\n");
	test_smalloc();

	printf("==== fd\n");
	test_fd();

	printf("==== syscall\n");
	test_syscall();

	printf("==== end\n");
	exit(0);
}
