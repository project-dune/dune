/*
 * procmap.c - Parse linux process map information.
 */

/*
 * Format:
 * start addr-end addr perms offset dev(xx:yy) inode path
 *
 * Permsissions:
 *                     rwxp
 *                     ||||
 *   Readable ---------+|||
 *   (r or -)           |||
 *   Writable ----------+||
 *   (w or -)            ||
 *   Executable ---------+|
 *   (X or -)             |
 *   Private/Shared ------+
 *   (p or s)
 *
 * Special Paths:
 *  - <filename>
 *  - anonymous
 *  - [heap]
 *  - [stack]
 *  - [vsyscall]
 *  - [vdso]
 *
 * Example /proc/self/maps:
 * 00400000-0040b000 r-xp 00000000 fe:00 917797                             /bin/cat
 * 0060a000-0060b000 r--p 0000a000 fe:00 917797                             /bin/cat
 * 0060b000-0060c000 rw-p 0000b000 fe:00 917797                             /bin/cat
 * 022cf000-022f0000 rw-p 00000000 00:00 0                                  [heap]
 * 7fe598687000-7fe59881e000 r-xp 00000000 fe:00 917523                     /lib/libc-2.15.so
 * 7fe59881e000-7fe598a1e000 ---p 00197000 fe:00 917523                     /lib/libc-2.15.so
 * 7fe598a1e000-7fe598a22000 r--p 00197000 fe:00 917523                     /lib/libc-2.15.so
 * 7fe598a22000-7fe598a24000 rw-p 0019b000 fe:00 917523                     /lib/libc-2.15.so
 * 7fe598a24000-7fe598a28000 rw-p 00000000 00:00 0 
 * 7fe598a28000-7fe598a49000 r-xp 00000000 fe:00 917531                     /lib/ld-2.15.so
 * 7fe598c37000-7fe598c3a000 rw-p 00000000 00:00 0 
 * 7fe598c47000-7fe598c48000 rw-p 00000000 00:00 0 
 * 7fe598c48000-7fe598c49000 r--p 00020000 fe:00 917531                     /lib/ld-2.15.so
 * 7fe598c49000-7fe598c4a000 rw-p 00021000 fe:00 917531                     /lib/ld-2.15.so
 * 7fe598c4a000-7fe598c4b000 rw-p 00000000 00:00 0 
 * 7fff601ca000-7fff601eb000 rw-p 00000000 00:00 0                          [stack]
 * 7fff601ff000-7fff60200000 r-xp 00000000 00:00 0                          [vdso]
 * ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0                  [vsyscall]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dune.h"

static int get_type(const char *path)
{
	if (path[0] != '[' && path[0] != '\0')
		return PROCMAP_TYPE_FILE;
	if (path[0] == '\0')
		return PROCMAP_TYPE_ANONYMOUS;
	if (strcmp(path, "[heap]") == 0)
		return PROCMAP_TYPE_HEAP;
	if (strncmp(path, "[stack", 6) == 0)
		return PROCMAP_TYPE_STACK;
	if (strcmp(path, "[vsyscall]") == 0)
		return PROCMAP_TYPE_VSYSCALL;
	if (strcmp(path, "[vdso]") == 0)
		return PROCMAP_TYPE_VDSO;
	return PROCMAP_TYPE_UNKNOWN;
}

void dune_procmap_iterate(dune_procmap_cb cb)
{
	struct dune_procmap_entry e;
	FILE *map;
	unsigned int dev1, dev2, inode;
	char read, write, execute, private;
	char line[512];
	char path[256];

	map = fopen("/proc/self/maps", "r");
	if (map == NULL) {
		printf("Could not open /proc/self/maps!\n");
		abort();
	}

	setvbuf(map, NULL, _IOFBF, 8192);

	while (!feof(map)) {
		path[0] = '\0';
		if (fgets(line, 512, map) == NULL)
			break;
		sscanf((char *)&line, "%lx-%lx %c%c%c%c %lx %x:%x %d %s",
			  &e.begin, &e.end,
			  &read, &write, &execute, &private, &e.offset,
			  &dev1, &dev2, &inode, path);
		e.r = (read == 'r');
		e.w = (write == 'w');
		e.x = (execute == 'x');
		e.p = (private == 'p');
		e.path = path;
		e.type = get_type(path);
		cb(&e);
	}
	fclose(map);
}

static void __dune_procmap_dump_helper(const struct dune_procmap_entry *e)
{
	printf("0x%016lx-0x%016lx %c%c%c%c %08lx %s\n",
			   e->begin, e->end,
			   e->r ? 'R' : '-',
			   e->w ? 'W' : '-',
			   e->x ? 'X' : '-',
			   e->p ? 'P' : 'S',
			   e->offset,
			   e->path);
}

void dune_procmap_dump()
{
	printf("--- Process Map Dump ---\n");
	dune_procmap_iterate(&__dune_procmap_dump_helper);
}

