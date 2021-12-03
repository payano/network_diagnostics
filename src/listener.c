#include <netinet/in.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include <string.h>

#include "listener.h"
#include "print.h"
#include "common.h"

struct mode_specific {
	int sockfd;
};
#define BUF_SIZ		1024

int listener_init(struct tester_params *data)
{
	char sender[INET6_ADDRSTRLEN];
	int ret, i;
	int sockopt;
	struct ifreq ifopts;	/* set promiscuous mode */
	struct ifreq if_ip;	/* get ip addr */
	struct sockaddr_storage their_addr;

	data->specific = calloc(1, sizeof(struct mode_specific));
	if(!data->specific) {
		printf("Couldn't allocate memory.\n");
		return 1;
	}

	data->specific->sockfd = socket(PF_PACKET, SOCK_RAW,
	                                _htobe16(ETHER_TYPE_IPV4));

	if (-1 == data->specific->sockfd) {
		perror("listener: socket");
		return -1;
	}

	/* Set interface to promiscuous mode - do we need to do this every time? */
	printf("data->eth_if: %s\n", data->eth_if);
	strncpy(ifopts.ifr_name, data->eth_if, IFNAMSIZ-1);
	ioctl(data->specific->sockfd, SIOCGIFFLAGS, &ifopts);
	ifopts.ifr_flags |= IFF_PROMISC;
	ioctl(data->specific->sockfd, SIOCSIFFLAGS, &ifopts);
	/* Allow the socket to be reused - incase connection is closed prematurely */
	if (setsockopt(data->specific->sockfd, SOL_SOCKET, SO_REUSEADDR, &sockopt, sizeof sockopt) == -1) {
		perror("setsockopt");
		close(data->specific->sockfd);
		exit(EXIT_FAILURE);
	}
	/* Bind to device */
	if (setsockopt(data->specific->sockfd, SOL_SOCKET, SO_BINDTODEVICE, data->eth_if, IFNAMSIZ-1) == -1)	{
		perror("SO_BINDTODEVICE");
		close(data->specific->sockfd);
		exit(EXIT_FAILURE);
	}

	return 0;
}

int listener_main(struct tester_params *data)
{
	uint8_t buf[BUF_SIZ];
	ssize_t numbytes;

	numbytes = recvfrom(data->specific->sockfd, buf, BUF_SIZ, 0, NULL, NULL);
	print_raw_packet(buf, numbytes);
	return 0;
}

void listener_cleanup(struct tester_params *data)
{
	free(data->specific);
}
