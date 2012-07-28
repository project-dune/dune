#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <err.h>
#include <string.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#include "sthread.h"

static int _imp;

static void do_handle_dude(int s)
{
	char buf[4096];
	int rc;
	char *p;
	int fd;

	rc = read(s, buf, sizeof(buf) - 1);
	if (rc <= 0)
		return;

	buf[rc] = 0;

	p = strchr(buf, '\r');
	if (p)
		*p = 0;

	p = strchr(buf, '\n');
	if (p)
		*p = 0;

	if (strncmp(buf, "GET / HTTP/", 11) != 0)
		return;

	snprintf(buf, sizeof(buf),
		 "HTTP/1.0 200 OK\nContent-Type: text/html\n\n");

	if (write(s, buf, strlen(buf)) != strlen(buf))
		return;

	fd = open("index.html", O_RDONLY);
	if (fd == -1)
		return;

	while ((rc = read(fd, buf, sizeof(buf))) > 0) {
		if (write(s, buf, rc) != rc) {
			close(fd);
			return;
		}
	}

	close(fd);
	return;
}

static void *pthread(void *arg)
{
	int s = (long) arg;

	do_handle_dude(s);

	return NULL;
}

static void handle_dude(int s)
{
	pthread_t pt;
	sthread_t st;
	sc_t sc;

//	printf("Got connection\n");

	switch (_imp) {
	case 0:
		do_handle_dude(s);
		break;

	case 1:
		if (pthread_create(&pt, NULL, pthread, (void*) (long) s))
			err(1, "pthread_create()");

		if (pthread_join(pt, NULL))
			err(1, "pthread_join()");
		break;

	case 2:
		if (fork() == 0) {
			do_handle_dude(s);
			exit(0);
		} else
			wait(NULL);
		break;

	case 3:
		sc_init(&sc);
		sc_fd_add(&sc, s, PROT_READ | PROT_WRITE);
		sc_sys_add(&sc, SYS_open);
		sc_sys_add(&sc, SYS_close);

		if (sthread_create(&st, &sc, pthread, (void*) (long) s))
			err(1, "sthread_create()");

		if (sthread_join(st, NULL))
			err(1, "sthread_join()");
		break;

	default:
		printf("Unknown implementation %d\n", _imp);
		break;
	}
}

static void pwn(void)
{
	int s, dude;
	int one = 1;
	struct sockaddr_in s_in;

	if ((s = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1)
		err(1, "socket()");

	if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) == -1)
		err(1, "setsockopt()");

	memset(&s_in, 0, sizeof(s_in));
	s_in.sin_family      = PF_INET;
	s_in.sin_port        = htons(80);
	s_in.sin_addr.s_addr = INADDR_ANY;

	if (bind(s, (struct sockaddr*) &s_in, sizeof(s_in)) == -1)
		err(1, "bind()");

	if (listen(s, 5) == -1)
		err(1, "listen()");

	while ((dude = accept(s, NULL, NULL)) != -1) {
		handle_dude(dude);
		close(dude);
	}

	err(1, "accept()");
	close(s);
}

int main(int argc, char *argv[])
{
	if (argc > 1)
		_imp = atoi(argv[1]);

	printf("Pwning\n");

	if (_imp == 3) {
		if (sthread_init())
			err(1, "sthread_init()");
	}

	pwn();

	exit(0);
}
