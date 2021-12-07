#include <ifaddrs.h>
#include <linux/in.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>

#include "network_helper.h"
#include "common.h"

int network_helper_get_time(struct timespec *ts)
{
	if (clock_gettime(CLOCK_REALTIME, ts) == -1) {
		perror("clock_gettime");
		return EXIT_FAILURE;
	}
	return 0;
}

int network_helper_init_packet(struct test_packet *packet, uint16_t hdr_type,
                               struct timespec *time)
{
	struct timespec ts;
	struct timespec *time_ptr;

	if(!time) {
		time_ptr = &ts;
		network_helper_get_time(time_ptr);
	} else {
		time_ptr = time;
	}

	packet->ts_sec  = time_ptr->tv_sec;
	packet->ts_nsec = time_ptr->tv_nsec;
	packet->hdr.type = hdr_type;
	packet->hdr.version = HEADER_VERSION;
	return 0;
}

/* Will give ms difference */
//int network_helper_compare(struct test_packet *packet, int sz)
//{
//	struct timespec ts;
//	if (clock_gettime(CLOCK_REALTIME, &ts) == -1) {
//		perror("clock_gettime");
//		return EXIT_FAILURE;
//	}
//
//	printf("Packet information [\n");
//
//	ts.tv_sec -= packet->ts_sec;
//	ts.tv_nsec -= packet->ts_nsec;
//	float sec = ts.tv_sec + (ts.tv_nsec * 1e-9);
//
//	printf("  type: 0x%x\n", packet->hdr.type);
//	printf("  version: 0x%x\n", packet->hdr.version);
//
//	printf("  delay[s]: %f\n", sec);
//	printf("]\n");
//	return 0;
//}


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

int network_helper_vlan_found(uint8_t *eth_type)
{
	void *eth_v = eth_type;
	uint16_t *eth16 = eth_v;
	return *eth16 == _htobe16(0x8100) ? 1 : 0;

}

int network_helper_valid_hdr_type(uint16_t ver)
{
	switch(ver){
	case HEADER_RESP_CLIENT: /* fall-through */
	case HEADER_RESP_SERVER: return 0;
	default: return 1;
	}
}

int network_helper_valid_hdr_version(uint16_t ver)
{
	switch(ver){
	case HEADER_VERSION: return 0;
	default: return 1;
	}
}
