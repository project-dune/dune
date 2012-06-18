#include <stdio.h>
#include <stdlib.h>

#include "libdune/dune.h"


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

	return 0;
}
