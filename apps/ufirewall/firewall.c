/*
 * Userspace firewall rule parser and processor.
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/queue.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <sandbox.h>
#include <boxer.h>

#include "firewall.h"

#define FW_TYPE_BIND_ALLOW	1
#define FW_TYPE_CONNECT_ALLOW	2
#define FW_TYPE_CONNECT_DENY	3

#define FW_PORT_ANY		0
#define FW_IP_ANY		0
#define FW_MASK_SINGLE		0xffffffff

struct fw_rule;
typedef SLIST_ENTRY(fw_rule) fw_entry_t;

struct fw_rule {
	fw_entry_t	link;
	int 		type;	// Rule type
	uint16_t	port;	// Port number
	uint32_t	ip;	// IPv4 address
	uint32_t	mask;	// IPv4 netmask
};

SLIST_HEAD(rules_head, fw_rule);

static struct rules_head rules;

#define STR_COMMENT		"#"
#define STR_ALLOW_BIND		"allow bind"
#define STR_ALLOW_CONNECT	"allow connect"
#define STR_DENY_CONNECT	"deny connect"

static int firewall_parse(const char *fwrules)
{
	FILE *f = NULL;
	char port[8];
	char ip[20];
	char mask[20];
	struct in_addr inp;

	f = fopen(fwrules, "r+");
	if (f == NULL) {
		printf("Cannot open '%s'\n", fwrules);
		return -1;
	}

	printf("--- Begin Firewall Rules ---\n");
	while (1) {
		struct fw_rule *r;
		char *str;
		char buf[100];

		if (feof(f))
			return 0;

		r = (struct fw_rule *)malloc(sizeof(struct fw_rule));
		str = fgets(buf, 100, f);
		if (str == NULL)
			goto done;

		if (!strncmp(STR_COMMENT, str, strlen(STR_COMMENT))) {
			// Comment
			free(r);
			continue;
		} else if (!strcmp("\n", str)) {
			// Blank line
			free(r);
			continue;
		} else if (!strncmp(STR_ALLOW_BIND, str, strlen(STR_ALLOW_BIND))) {
			sscanf(str, STR_ALLOW_BIND " %s", port);
			r->type = FW_TYPE_BIND_ALLOW;
			if (strcmp(port, "*") == 0)
				r->port = FW_PORT_ANY;
			else
				r->port = atoi(port);
			printf(STR_ALLOW_BIND " %d\n", r->port);
		} else if (!strncmp(STR_ALLOW_CONNECT, str, strlen(STR_ALLOW_CONNECT))) {
			sscanf(str, STR_ALLOW_CONNECT " %s %s %s", port, ip, mask);
			r->type = FW_TYPE_CONNECT_ALLOW;
			if (strcmp(port, "*") == 0)
				r->port = FW_PORT_ANY;
			else
				r->port = atoi(port);
			if (inet_aton(ip, &inp) < 0) {
				printf("Failed to parse ip address!\n");
				free(r);
				return -1;
			}
			r->ip = inp.s_addr;
			if (inet_aton(mask, &inp) < 0) {
				printf("Failed to parse ip mask!\n");
				free(r);
				return -1;
			}
			r->mask = inp.s_addr;
			printf(STR_ALLOW_CONNECT " %d %s %s\n", r->port, ip, mask);
		} else if (!strncmp(STR_DENY_CONNECT, str, strlen(STR_DENY_CONNECT))) {
			sscanf(str, STR_DENY_CONNECT " %s %s %s", port, ip, mask);
			r->type = FW_TYPE_CONNECT_DENY;
			if (strcmp(port, "*") == 0)
				r->port = FW_PORT_ANY;
			else
				r->port = atoi(port);
			if (inet_aton(ip, &inp) < 0) {
				printf("Failed to parse ip address!\n");
				free(r);
				return -1;
			}
			r->ip = inp.s_addr;
			if (inet_aton(mask, &inp) < 0) {
				printf("Failed to parse ip mask!\n");
				free(r);
				return -1;
			}
			r->mask = inp.s_addr;
			printf(STR_DENY_CONNECT " %d %s %s\n", r->port, ip, mask);
		} else {
			// Unknown!
			printf("Unknown rule:\n%s\n", str);
			return -1;
		}

		SLIST_INSERT_HEAD(&rules, r, link);
	}

done:
	printf("--- End Firewall Rules ---\n");

	return 0;
}

bool firewall_check_bind(uint16_t port)
{
	struct fw_rule *p;

	for (p = rules.slh_first; p != NULL; p = p->link.sle_next)
	{
		if (p->type == FW_TYPE_BIND_ALLOW) {
			if (p->port == FW_PORT_ANY)
				return true;
			if (p->port == port)
				return true;
		}
	}

	return false;
}

bool firewall_check_connect(uint16_t port, uint32_t ip)
{
	struct fw_rule *p;

	for (p = rules.slh_first; p != NULL; p = p->link.sle_next)
	{
		if (p->type == FW_TYPE_CONNECT_ALLOW) {
			if ((ip & p->ip) == (ip & p->mask)) {
				if (p->port == FW_PORT_ANY)
					return true;
				if (p->port == port)
					return true;
			}
		}
		if (p->type == FW_TYPE_CONNECT_DENY) {
			if ((ip & p->ip) == (ip & p->mask)) {
				if (p->port == FW_PORT_ANY)
					return false;
				if (p->port == port)
					return false;
			}
		}
	}

	return false;
}

int firewall_init(void)
{
	SLIST_INIT(&rules);

	printf("parsing 'ufw.rules'\n");
	if (firewall_parse("ufw.rules") < 0) {
		return -1;
	}

	return 0;
}

static int check_bind(int sock, const struct sockaddr *addr, socklen_t len)
{
	const struct sockaddr_in *a = (const struct sockaddr_in *)addr;

        // Only support IPv4
	if (len == sizeof(*a) && a->sin_family == AF_INET) {
		if (!firewall_check_bind(ntohs(a->sin_port)))
			return 0;
	}

        return 1;
}

static int check_connect(int sock, const struct sockaddr *addr, socklen_t len)
{
	const struct sockaddr_in *a = (const struct sockaddr_in *)addr;

        // Only support IPv4
	if (len == sizeof(*a) && a->sin_family == AF_INET) {
		if (!firewall_check_connect(ntohs(a->sin_port),
					    a->sin_addr.s_addr))
		{
			return 0;
		}
	}

	return 1;
}

static int syscall_monitor(struct dune_tf *tf)
{
	switch (tf->rax) {
	case __NR_bind:
        {
		int status = check_bind((int) ARG0(tf),
				        (const struct sockaddr *) ARG1(tf),
				        (socklen_t) ARG2(tf));
                if (!status)
                    tf->rax = -EPERM;
                return status;
        }
	case __NR_connect:
        {
		int status = check_connect((int) ARG0(tf),
				           (const struct sockaddr *) ARG1(tf),
				           (socklen_t) ARG2(tf));
                if (!status)
                    tf->rax = -EPERM;
                return status;
        }
	default:
		return 1;
	}
}

int main(int argc, char *argv[])
{
	if (firewall_init() != 0) {
		printf("Cannot parse firewall rules exiting...\n");
		return 1;
	}
	boxer_register_syscall_monitor(syscall_monitor);
	return boxer_main(argc, argv);
}

