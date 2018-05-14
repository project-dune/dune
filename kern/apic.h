u32 apic_id(void);
void apic_init(void);
void apic_init_rt_entry(void);
u32 apic_get_cpu_id_for_apic(u32 apic, bool *error);
void apic_send_ipi(u8 vector, u32 destination_apic_id);
void apic_write_eoi(void);
