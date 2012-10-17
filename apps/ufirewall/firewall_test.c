#include <stdio.h>
#include <errno.h>
#include <string.h>

#include <stdint.h>

#include <sys/socket.h>
#include <netinet/in.h>

int test_bind(uint16_t port)
{
	int fd;
	socklen_t len;
	struct sockaddr_in saddr;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		perror("socket: ");
		return -1;
	}

	bzero(&saddr, sizeof(saddr));
	saddr.sin_family = AF_INET;
	saddr.sin_addr.s_addr = htonl(INADDR_ANY);
	saddr.sin_port = htons(port);
	len = sizeof(saddr);

	if (bind(fd, (struct sockaddr *)&saddr, len) < 0) {
		close(fd);
		return -1;
	}

	close(fd);
	return 0;
}

int test_connect(const char *ip, uint16_t port)
{
	int fd;
	socklen_t len;
	struct sockaddr_in caddr;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		perror("socket: ");
		return -1;
	}

	bzero(&caddr, sizeof(caddr));
	caddr.sin_family = AF_INET;
	inet_pton(AF_INET, ip, &caddr.sin_addr);
	caddr.sin_port = htons(port);
	len = sizeof(caddr);

	if (connect(fd, (struct sockaddr *)&caddr, len) < 0) {
		close(fd);
		return -1;
	}

	close(fd);
	return 0;
}

int main(int argc, char *argv[])
{
	printf("Userlevel Firewall Test Application!\n");

	printf("bind to port 1234: ");
	if (test_bind(1234) < 0) {
		printf("failed!\n");
		perror("cause");
		return 1;
	}
	printf("succeeded\n");

	printf("bind to port 4321 (expect failure): ");
	if (test_bind(4321) == 0) {
		printf("succeeded!\n");
		return 1;
	}
	printf("failed\n");

	printf("connect to www.scs.stanford.edu(171.66.3.9):80: ");
	if (test_connect("171.66.3.9", 80) < 0) {
		printf("failed!\n");
		perror("cause");
		return 1;
	}
	printf("succeeded\n");

	printf("connect to market.scs.stanford.edu(171.66.3.10):22: ");
	if (test_connect("171.66.3.10", 22) == 0) {
		printf("succeeded!\n");
		return 1;
	}
	printf("failed\n");

	printf("all tests passed!\n");

	return 0;
}
