#define HUGEPAGES_GET_CR3 _IOR(0xFF, 1, unsigned long)
#define HUGEPAGES_READ_MEM _IOWR(0xFF, 2, unsigned long)
#define HUGEPAGES_GET_EPTP _IOR(0xFF, 3, unsigned long)

static inline unsigned long get_cr3(void)
{
	unsigned long cr3;
	asm("mov %%cr3, %0\n" : "=r" (cr3));
	return cr3;
}
