#include <netinet/in.h>
#include <pcap/pcap.h>
#include <stdlib.h>

#include "listener.h"
#include "print.h"
#include "common.h"

struct mode_specific {
	pcap_t *pcap_handle;
};

int listener_init(struct tester_params *data)
{
	int ret;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program filter;
	char filter_exp[100];

	data->specific = calloc(1, sizeof(struct mode_specific));
	if(!data->specific) {
		printf("Couldn't allocate memory.\n");
		return 1;
	}

	data->specific->pcap_handle = pcap_create(data->eth_if, errbuf);
	if(!data->specific->pcap_handle) {
		printf("Error: pcap_create %s\n", errbuf);
		return 1;
	}

	ret = pcap_set_timeout(data->specific->pcap_handle, PCAP_TIMEOUT);
	if(ret) {
		printf("Error setting timeout\n");
		return ret;
	}

	ret = pcap_activate(data->specific->pcap_handle);
	if(ret) {
		printf("Error pcap_activate: %s\n", pcap_statustostr(ret));
		return 1;
	}

	snprintf(filter_exp, sizeof(filter_exp), "dst %s and src %s",
	         data->ipv4_dst_str, data->ipv4_src_str);

	ret = pcap_compile(data->specific->pcap_handle, &filter,
	                   filter_exp, 0, PCAP_NETMASK_UNKNOWN);
	if(ret) {
		printf("Error compiling pcap filter\n");
		return ret;
	}

	ret = pcap_setfilter(data->specific->pcap_handle, &filter);
	if(ret)
		printf("Error setting filter\n");

	return ret;
}

int listener_main(struct tester_params *data)
{
	struct pcap_pkthdr *pkt_header;
	const u_char *pkt_data;
	int ret;

	while(!data->exit_program) {
		ret = pcap_next_ex(data->specific->pcap_handle, &pkt_header,
		                   &pkt_data);

		/* error reading packet */
		if(1 != ret) {
			printf("ERROR\n");
			return 1;
		}
		print_eth_header(data, pkt_data);
		print_ipv4_header(data, pkt_data);
	}
	return 0;
}

void listener_cleanup(struct tester_params *data)
{
	if(data->specific->pcap_handle)
		pcap_close(data->specific->pcap_handle);
	free(data->specific);
}
