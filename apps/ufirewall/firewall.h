/*
 * Userlevel firewall API
 */

int firewall_init(void);
bool firewall_check_connect(uint16_t port, uint32_t ip);
bool firewall_check_bind(uint16_t port);

