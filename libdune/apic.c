/* These functions are used to send and receive posted IPIs with an x2APIC.
*/

#define _GNU_SOURCE

#include <malloc.h>
#include <sched.h>
#include <sys/sysinfo.h>

#include "dune.h"
#include "cpu-x86.h"

//the value to write to the EOI register when an interrupt handler has finished
#define APIC_ID_MSR 0x802
#define APIC_ICR_MSR 0x830
#define APIC_EOI_MSR 0x80B

#define APIC_DM_FIXED 0x00000
#define NMI_VECTOR 0x02
#define APIC_DM_NMI 0x00400
#define APIC_DEST_PHYSICAL 0x00000
#define EOI_ACK 0x0

static int *apic_routing;
static int num_rt_entries;

uint32_t dune_apic_id()
{
	long long apic_id;
	rdmsrl(APIC_ID_MSR, apic_id);
	return (uint32_t)apic_id;
}

bool dune_setup_apic()
{
	num_rt_entries = get_nprocs_conf();
	apic_routing = malloc(num_rt_entries * sizeof(int));
	if (!apic_routing) {
		return false;
	}
	num_rt_entries = get_nprocs_conf();
	memset(apic_routing, -1, num_rt_entries * sizeof(int));
	asm("mfence" ::: "memory");
	return true;
}

void dune_apic_free()
{
	free(apic_routing);
}

void dune_apic_init_rt_entry()
{
	int core_id = sched_getcpu();
	apic_routing[core_id] = dune_apic_id();
	asm("mfence" ::: "memory");
}

uint32_t dune_apic_id_for_cpu(uint32_t cpu, bool *error)
{
	if (cpu >= num_rt_entries) {
		if (error) *error = true;
		return 0;
	}
	return apic_routing[cpu];
}

static inline unsigned int __prepare_ICR(unsigned int shortcut, int vector, unsigned int dest)
{
	unsigned int icr = shortcut | dest;

	switch (vector) {
	default:
		icr |= APIC_DM_FIXED | vector;
		break;
	case NMI_VECTOR:
		icr |= APIC_DM_NMI;
		break;
	}
	return icr;
}

void dune_apic_send_ipi(uint8_t vector, uint32_t destination_apic_id)
{
	uint32_t low = __prepare_ICR(0, vector, APIC_DEST_PHYSICAL);
	wrmsrl(APIC_ICR_MSR, (((uint64_t)destination_apic_id) << 32) | low);
}

/* apic_eoi
 * Writes to the End-of-Interrupt register for the local APIC for the core
 * that executes this function to indicate that the interrupt handler has
 * finished.
*/
void dune_apic_eoi()
{
	wrmsrl(APIC_EOI_MSR, EOI_ACK);
}
