/*
 * page.c - page management
 */

#define _GNU_SOURCE

#include <errno.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>

#include "dune.h"

#define GROW_SIZE	512

static pthread_mutex_t page_mutex = PTHREAD_MUTEX_INITIALIZER;

struct page *pages;
static struct page_head pages_free;
int num_pages;

static void * do_mapping(void *base, unsigned long len)
{
	void *mem;

	mem = mmap((void *) base, len,
		   PROT_READ | PROT_WRITE,
		   MAP_FIXED | MAP_HUGETLB | MAP_PRIVATE |
		   MAP_ANONYMOUS, -1, 0);

	if (mem != (void *) base) {
		// try again without huge pages
		mem = mmap((void *) base, len,
			   PROT_READ | PROT_WRITE,
			   MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS,
			   -1, 0);
		if (mem != (void *) base)
			return NULL;
	}

	return mem;
}

static int grow_size(void)
{
	int i;
	int new_num_pages = num_pages + GROW_SIZE;
	void *ptr;

	ptr = do_mapping((void *) PAGEBASE + num_pages * PGSIZE,
			 GROW_SIZE * PGSIZE);
	if (!ptr)
		return -ENOMEM;

	for (i = num_pages; i < new_num_pages; i++) {
		pages[i].ref = 0;
		SLIST_INSERT_HEAD(&pages_free, &pages[i], link);
	}

	num_pages = new_num_pages;

	return 0;
}

void dune_page_stats(void)
{
	int i;
	int num_alloc = 0;

	for (i = 0; i < num_pages; i++) {
		if (pages[i].ref != 0)
			num_alloc++;
	}

	dune_printf("DUNE Page Allocator: Alloc %d, Free %d, Total %d\n",
			   num_alloc, num_pages - num_alloc, num_pages);
}

struct page * dune_page_alloc(void)
{
	struct page *pg;

	pthread_mutex_lock(&page_mutex);
	if (SLIST_EMPTY(&pages_free)) {
		if (grow_size()) {
			pthread_mutex_unlock(&page_mutex);
			return NULL;
		}
	}

	pg = SLIST_FIRST(&pages_free);
	SLIST_REMOVE_HEAD(&pages_free, link);
	pthread_mutex_unlock(&page_mutex);

	dune_page_get(pg);

	return pg;
}

void dune_page_free(struct page *pg)
{
	assert(!pg->ref);
	pthread_mutex_lock(&page_mutex);
	SLIST_INSERT_HEAD(&pages_free, pg, link);
	pthread_mutex_unlock(&page_mutex);
}

bool dune_page_isfrompool(physaddr_t pa)
{
	// XXX: Insufficent?
	return (pa >= PAGEBASE) && (pa < PAGEBASE + num_pages*PGSIZE);
}

int dune_page_init(void)
{
	int i;
	void *mem;

	SLIST_INIT(&pages_free);
	num_pages = GROW_SIZE;

	mem = do_mapping((void *) PAGEBASE, num_pages * PGSIZE);
	if (!mem)
		return -ENOMEM;

	pages = malloc(sizeof(struct page) * MAX_PAGES);
	if (!pages)
		goto err;

	for (i = 0; i < num_pages; i++) {
		pages[i].ref = 0;
		SLIST_INSERT_HEAD(&pages_free, &pages[i], link);
	}

	return 0;

err:
	munmap((void *) PAGEBASE, num_pages * PGSIZE);
	return -ENOMEM;
}
