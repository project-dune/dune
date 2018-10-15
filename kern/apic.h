u32 dune_apic_id(void);
bool dune_apic_init(void);
void dune_apic_free(void);
void dune_apic_init_rt_entry(void);
u32 dune_apic_get_cpu_id_for_apic(u32 apic, bool *error);
void dune_apic_send_ipi(u8 vector, u32 destination_apic_id);
void dune_apic_write_eoi(void);
