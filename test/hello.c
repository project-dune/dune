#include <stdio.h>
#include <stdlib.h>

#include "libdune/dune.h"
#include "libdune/cpu-x86.h"

static void divide_by_zero_handler(struct dune_tf *tf)
{
	printf("Divided by zero!\n");
}

int main(int argc, char *argv[])
{
	int ret;

	printf("hello: not running dune yet\n");

	ret = dune_init();
	if (ret) {
		printf("failed to initialize dune\n");
		return ret;
	}

	printf("hello: now printing from dune mode\n");

	dune_register_interrupt_handler(T_DIVIDE, divide_by_zero_handler);

	ret = 1 / ret; /* divide by zero */

	printf("Still alive\n");

	return 0;
}
