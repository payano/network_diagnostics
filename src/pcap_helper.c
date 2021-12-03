#include <string.h>

#include <netinet/in.h>
#include <pcap/pcap.h>

#include "pcap_helper.h"

#define ETH_PRINT_SPACING 10

int pcap_helper_list_eth_if(char *eth_if)
{
	int ret;
	pcap_if_t *pcap_devs;
	pcap_if_t *d;
	char errbuf[PCAP_ERRBUF_SIZE];

	ret = pcap_findalldevs(&pcap_devs, errbuf);
	if(PCAP_ERROR == ret) {
		printf("Error: %s\n", errbuf);
		return 1;
	}

	for (d = pcap_devs ; d != NULL; d = d->next) {
		pcap_addr_t *a;
		for(a = d->addresses; a != NULL; a = a->next) {
			struct sockaddr_in *sock_addr;
			uint32_t a_addr;
			int i = 0;

			if (a->addr->sa_family != AF_INET)
				continue;
			printf("  %s", d->name);
			for(; i < ETH_PRINT_SPACING - strlen(d->name); ++i)
				printf(" ");

			sock_addr = (struct sockaddr_in *)a->addr;
			a_addr = sock_addr->sin_addr.s_addr;
			printf("[%d.", a_addr & 0xff);
			printf("%d.", (a_addr >> 8) & 0xff);
			printf("%d.", (a_addr >> 16) & 0xff);
			printf("%d]", (a_addr >> 24) & 0xff);
			printf("\n");
		 }
	}

	pcap_freealldevs(pcap_devs);
	return 0;
}

int pcap_helper_find_eth_if(char *eth_if)
{
	int ret;
	pcap_if_t *pcap_devs;
	pcap_if_t *d;
	char errbuf[PCAP_ERRBUF_SIZE];

	ret = pcap_findalldevs(&pcap_devs, errbuf);
	if(PCAP_ERROR == ret) {
		printf("Error: %s\n", errbuf);
		return 1;
	}

	ret = -1;
	for (d = pcap_devs; d != NULL; d = d->next) {
		pcap_addr_t *addr;
		for(addr = d->addresses; addr != NULL; addr = addr->next) {
			if (addr->addr->sa_family != AF_INET)
				continue;

			if(!strcmp(eth_if, d->name)) {
				ret = 0;
				goto end;
			}
		 }
	}

end:
	pcap_freealldevs(pcap_devs);
	return ret;
}
