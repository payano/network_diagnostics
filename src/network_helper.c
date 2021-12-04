#include <ifaddrs.h>
#include <linux/in.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>

#include "network_helper.h"
#include "common.h"

int network_helper_init_packet(struct test_packet *packet)
{
	struct timespec ts;
	int i;

	if (clock_gettime(CLOCK_REALTIME, &ts) == -1) {
		perror("clock_gettime");
		return EXIT_FAILURE;
	}

	packet->ts_sec  = ts.tv_sec;
	packet->ts_nsec = ts.tv_nsec;

	for(i = 0; i < PAYLOAD_SZ; ++i) {
		packet->payload[i] = i;
	}

	return 0;
}

/* Will give ms difference */
int network_helper_compare(struct timespec *ts1, uint64_t *result)
{
	struct timespec ts;
	if (clock_gettime(CLOCK_REALTIME, &ts) == -1) {
		perror("clock_gettime");
		return EXIT_FAILURE;
	}

	ts.tv_sec -= ts1->tv_sec;
	ts.tv_nsec -= ts1->tv_nsec;
	float sec = ts.tv_sec + (ts.tv_nsec * 1e-9);

	printf("delay[s]: %f\n", sec);
	return 0;
}


int network_helper_find_eth_if(const char *if_name)
{
	struct ifaddrs *if_list;
	struct ifaddrs *ifa;
	int ret;

	ret = getifaddrs(&if_list);
	if(ret) {
		perror("getifaddrs");
		return 1;
	}

	ret = 1; /* if not found return not ok */
	for(ifa = if_list; NULL != ifa; ifa = ifa->ifa_next)
	{
		if (!ifa->ifa_addr)
			continue;

		if(!strcmp(ifa->ifa_name, if_name)) {
			ret = 0;
			break;
		}
	}

	freeifaddrs(if_list);
	return ret;
}

void network_helper_print_eth_ifs()
{
	struct ifaddrs *if_list;
	struct ifaddrs *ifa;
	int ret;
	void *tmpAddrPtr;

	ret = getifaddrs(&if_list);
	if(ret) {
		perror("getifaddrs");
		return;
	}

	for(ifa = if_list; NULL != ifa; ifa = ifa->ifa_next)
	{
		if (!ifa->ifa_addr)
			continue;

		printf("  %s ", ifa->ifa_name);
		if (AF_INET == ifa->ifa_addr->sa_family) {
			struct sockaddr_in *ifaddr = (struct sockaddr_in *)ifa->ifa_addr;
			tmpAddrPtr= &ifaddr->sin_addr;
			uint8_t *addr = tmpAddrPtr;
			printf("[%d.", addr[0]);
			printf("%d.", addr[1]);
			printf("%d.", addr[2]);
			printf("%d",  addr[3]);
			printf("]");
		}
		printf("\n");
	}
	freeifaddrs(if_list);
}
