#include <sys/syscall.h>
#include <stdio.h>

#include <libdune/dune.h>
#include "boxer.h"

static int syscall_monitor(struct dune_tf *tf)
{
	switch (tf->rax) {
	case SYS_open:
		printf("opening file %s\n", (char*) ARG0(tf));
		break;
	}

	return 1;
}

int main(int argc, char *argv[])
{
	boxer_register_syscall_monitor(syscall_monitor);
	return boxer_main(argc, argv);
}
