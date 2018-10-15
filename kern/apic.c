#define _GNU_SOURCE

#include <linux/mm.h>
#include <linux/slab.h>
#include <asm/ipi.h>

#include "dune.h"

#define XAPIC_EOI_OFFSET 0xB0
#define APIC_EOI_ACK 0x0

static int *apic_routing;
static int num_rt_entries;

#define BY_APIC_TYPE(x, x2) if (x2apic_enabled()) { x2; } else { x; }

u32 dune_apic_id(void)
{
	return read_apic_id();
}

/* dune_highest_apic_id
 * Returns the highest APIC ID in the system
 */
static u32 dune_highest_apic_id(bool *error)
{
	int ret = -1;
	int cpu;

	if (error) *error = false;
	for_each_possible_cpu(cpu) {
		int apic_id = per_cpu(x86_cpu_to_apicid, cpu);
		if (apic_id > ret) ret = apic_id;
	}
	if (ret == -1) {
		if (error) *error = true;
		return 0;
	}
	return ret;
}

bool dune_apic_init(void)
{
	u32 highest_apic_id;
	bool error;
	highest_apic_id = dune_highest_apic_id(&error);
	if (error) {
		return false;
	}
	num_rt_entries = highest_apic_id + 1;
	apic_routing = kmalloc(num_rt_entries * sizeof(int), GFP_KERNEL);
	if (!apic_routing) {
		return false;
	}
	memset(apic_routing, -1, num_rt_entries * sizeof(int));
	asm("mfence" ::: "memory");
	return true;
}

void dune_apic_free(void)
{
	kfree(apic_routing);
}

void dune_apic_init_rt_entry(void)
{
	apic_routing[dune_apic_id()] = raw_smp_processor_id();
	asm("mfence" ::: "memory");
}

u32 dune_apic_get_cpu_id_for_apic(u32 apic, bool *error)
{
	if (apic >= num_rt_entries) {
		if (error) *error = true;
		return 0;
	}
	return apic_routing[apic];
}

/* dune_apic_write_x
 * Writes to the xAPIC's memory-mapped registrers.
 *
 * [reg] is the offset to write to within the memory region reserved
 * by the xAPIC.
 * [v] is the value to write.
 */
static inline void dune_apic_write_x(u32 reg, u32 v)
{
	volatile u32 *addr = (volatile u32 *)(APIC_BASE + reg);
	asm volatile("movl %0, %P1" : "=r" (v), "=m" (*addr) : "i" (0), "0" (v), "m" (*addr));
}

/* dune_apic_send_ipi_x2
 * Send an IPI to another local APIC. This function only supports x2APIC, not xAPIC.
 *
 * [vector] is the vector of the interrupt to send.
 * [destination_apic_id] is the ID of the local APIC that will receive the IPI.
 */
static void dune_apic_send_ipi_x2(u8 vector, u32 destination_apic_id)
{
	u32 low;
	low = __prepare_ICR(0, vector, APIC_DEST_PHYSICAL);
	x2apic_wrmsr_fence();
	wrmsrl(APIC_BASE_MSR + (APIC_ICR >> 4), ((__u64) destination_apic_id) << 32 | low);
}

/* dune_apic_send_ipi_x
 * Send an IPI to another local APIC. This function only supports xAPIC, not x2APIC.
 *
 * [vector] is the vector of the interrupt to send.
 * [destination_apic_id] is the ID of the local APIC that will receive the IPI.
 */
static void dune_apic_send_ipi_x(u8 vector, u8 destination_apic_id)
{
	__default_send_IPI_dest_field(destination_apic_id, vector, APIC_DEST_PHYSICAL);
}

/* dune_apic_send_ipi
 * Send an IPI to another local APIC. Determines whether the computer is equipped
 * with xAPICs or x2APICs and chooses the correct delivery method.
 *
 * [vector] is the vector of the interrupt to send.
 * [destination_apic_id] is the ID of the local APIC that will receive the IPI.
 */
void dune_apic_send_ipi(u8 vector, u32 destination_apic_id)
{
	BY_APIC_TYPE(dune_apic_send_ipi_x(vector, (u8)destination_apic_id),
				 dune_apic_send_ipi_x2(vector, destination_apic_id))
}

/* dune_apic_write_eoi
 * Acknowledges receipt of an interrupt to the local APIC by writing an acknowledgment to
 * the local APIC's EOI register. Determines whether the computer is equipped with xAPICs
 * or x2APICs and writes the acknowledgment accordingly.
 *
 * [vector] is the vector of the interrupt to send.
 * [destination_apic_id] is the ID of the local APIC that will receive the IPI.
 */
void dune_apic_write_eoi(void)
{
	BY_APIC_TYPE(dune_apic_write_x(XAPIC_EOI_OFFSET, APIC_EOI_ACK),
				 wrmsrl(APIC_BASE_MSR + (APIC_EOI >> 4), APIC_EOI_ACK))
}
