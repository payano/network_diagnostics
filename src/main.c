/*
 * main.c
 *
 *  Created on: Nov 30, 2021
 *      Author: evsejho
 */

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <libgen.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>

#include <netinet/in.h>
#include <pcap/pcap.h>

#define IPV4_ADDR_LEN 16
#define INTERFACE_LEN 20
#define ETH_PRINT_SPACING 10
#define PCAP_TIMEOUT 100

#define VLAN_TPID 0x8100

enum MODE {
	MODE_NONE = 0,
	MODE_SERVER,
	MODE_CLIENT
};

struct vlan_data {
	char ipv4_dest[IPV4_ADDR_LEN];
	char eth_if[INTERFACE_LEN];
	int vlan;
	enum MODE mode;
	pcap_t *pcap_handle;
	int exit;
};

struct vlan_tpid {
	uint16_t tpid:16;
	uint16_t pcp:3;
	uint16_t dei:1;
	uint16_t vid:12;
};

struct ipv4_header {
	uint32_t version:4;
	uint32_t ihl:4;
	uint32_t dscp:6;
	uint32_t ecn:2;
	uint32_t total_len:16;
	uint32_t id:16;
	uint32_t flags:3;
	uint32_t fragment_offset:13;
	uint32_t src_address:32;
	uint32_t dest_address:32;


};

struct vlan_data data = {0};

static void print_help(char *filename)
{
	printf("Usage %s:\n", basename(filename));
	printf("  -c       Mode client (sends data to server)\n");
	printf("  -s       Mode server (receives data from client)\n");
	printf("  -i       Network interface to use\n");
	printf("  -s       Server address to send data (used with -c)\n");
	printf("  -v       vlan id\n");
}

static char *ethertype_lookup(uint16_t ethertype)
{
	/* Source: https://en.wikipedia.org/wiki/EtherType */
	switch(ethertype){
	case 0x0800: return "IPV4";
	case 0x86DD: return "IPV6 (UNSUPPORTED)";
	default: return "UNSUPPORTED";
	}
}

__attribute__((unused))
static void print_raw_packet(const u_char *data, int len)
{
	for(int i = 0 ; i < 0x10 ; ++i)
		printf("0x%02x ", i);
	printf("\n");
	for(int i = 0 ; i < 0x10 ; ++i)
		printf("-----");


	for(int i = 0; i < len ; ++i) {
		if(0 == (i % 16)) printf("\n");
		printf("0x%02x ", data[i]);
	}
	printf("\n");
}

static void print_vlan_header(const uint16_t *vlan_hdr)
{
	struct vlan_tpid vlan;
	uint16_t *vlan16 = (uint16_t*)&vlan;
	memcpy(&vlan, vlan_hdr, sizeof(vlan));
	*vlan16 = htobe16(*vlan16);
	vlan16++;
	*vlan16 = htobe16(*vlan16);
	printf("VLAN id: %d, pcp: %d, dei: %d\n",
			vlan.vid, vlan.pcp, vlan.dei);
}

static void print_eth_header(const u_char *data)
{
	const uint16_t *vlan_tpid = (const uint16_t *)&data[12];
	const uint16_t *ethertype = (const uint16_t *)&data[12];
	printf("dst mac: %02x:%02x:%02x:%02x:%02x:%02x\n",
	       data[0], data[1], data[2], data[3], data[4], data[5]);
	printf("src mac: %02x:%02x:%02x:%02x:%02x:%02x\n",
	       data[6], data[7], data[8], data[9], data[10], data[11]);

	/* Check if vlan tag is found */
	if(VLAN_TPID == htobe16(*vlan_tpid))
	{
		print_vlan_header(vlan_tpid);
		ethertype++;
	}

	printf("ethertype: %s\n", ethertype_lookup(htobe16(*ethertype)));
}

static void print_ipv4_header(const u_char *data)
{
	const uint16_t *vlan_tpid = (const uint16_t *)&data[12];
	const u_char *ip_hdr_ptr;
	struct ipv4_header header;
	/* simplify this */
	if(VLAN_TPID == htobe16(*vlan_tpid))
	{
		vlan_tpid += 2;
		ip_hdr_ptr = (const u_char *)vlan_tpid;
	} else {
		vlan_tpid++;
		ip_hdr_ptr = (const u_char *)vlan_tpid;
	}

	memcpy(&header, ip_hdr_ptr, sizeof(header));
	uint32_t *ipv4_ptr = (uint32_t *)&header;
	int loop_sz = sizeof(header)/4;
	for(int i = 0; i < loop_sz; ++i) {
		*ipv4_ptr = htobe32(*ipv4_ptr);
		++ipv4_ptr;
	}

	printf("dst: %d.", (header.dest_address >> 24)& 0xff);
	printf("%d.",      (header.dest_address >> 16)& 0xff);
	printf("%d.",      (header.dest_address >> 8)& 0xff);
	printf("%d\n",     (header.dest_address )& 0xff);

	printf("src: %d.", (header.src_address >> 24)& 0xff);
	printf("%d.",      (header.src_address >> 16)& 0xff);
	printf("%d.",      (header.src_address >> 8)& 0xff);
	printf("%d\n",     (header.src_address )& 0xff);
}

void signal_handler(int sig){
	/* bail out... */
	data.exit = 1;
	printf("Stopping...\n");
}

static int list_eth_if(char *eth_if)
{
	int ret;
	pcap_if_t *pcap_devs;
	char errbuf[PCAP_ERRBUF_SIZE];

	ret = pcap_findalldevs(&pcap_devs, errbuf);
	if(PCAP_ERROR == ret) {
		printf("Error: %s\n", errbuf);
		return 1;
	}

	for (pcap_if_t *d = pcap_devs; d != NULL; d = d->next) {
		pcap_addr_t *a;
		for(a = d->addresses; a != NULL; a = a->next) {
			if (a->addr->sa_family != AF_INET)
				continue;
			printf("  %s", d->name);
			for(int i = 0; i < ETH_PRINT_SPACING - strlen(d->name); ++i)
				printf(" ");
			struct sockaddr_in *sock_addr = (struct sockaddr_in *)a->addr;
			uint32_t a_addr = sock_addr->sin_addr.s_addr;
			printf("[%d.", (a_addr >> 24) & 0xff);
			printf("%d.", (a_addr >> 16) & 0xff);
			printf("%d.", (a_addr >> 8) & 0xff);
			printf("%d] ", a_addr & 0xff);
			printf("\n");
		 }
	}

	pcap_freealldevs(pcap_devs);
	return 0;
}

static int find_eth_if(char *eth_if)
{
	int ret;
	pcap_if_t *pcap_devs;
	char errbuf[PCAP_ERRBUF_SIZE];

	ret = pcap_findalldevs(&pcap_devs, errbuf);
	if(PCAP_ERROR == ret) {
		printf("Error: %s\n", errbuf);
		return 1;
	}

	ret = -1;
	for (pcap_if_t *d = pcap_devs; d != NULL; d = d->next) {
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

static int get_params(int argc, char *argv[], struct vlan_data *data)
{
	int c = 0;

	if(argc < 2) {
		print_help(argv[0]);
		return -1;
	}

	static struct option long_options[] =
	{
//		/* These options set a flag. */
//		{"debug", no_argument,         verbose, 1},
//		{"brief",   no_argument,       &data->verbose_flag, 0},
//		/* These options don’t set a flag.
//	             We distinguish them by their indices. */
		{"client",         no_argument,       0, 'c'},
		{"dest_addr_ipv4", required_argument, 0, 'd'},
		{"interface",      required_argument, 0, 'i'},
		{"server",         no_argument,       0, 's'},
		{"vlan",           required_argument, 0, 'v'},
		{0, 0, 0, 0}
	};

	while (1)
	{
		/* getopt_long stores the option index here. */
		int option_index = 0;

		c = getopt_long (argc, argv, "cd:i:sv:",
		                 long_options, &option_index);

		/* Detect the end of the options. */
		if (c == -1)
			break;

		switch (c)
		{
		case 0:
			printf("FILE: %s, FUNC: %s, LINE: %d\n", __FILE__, __func__, __LINE__);
			/* If this option set a flag, do nothing else now. */
			if (long_options[option_index].flag != 0)
				break;
			printf ("option %s", long_options[option_index].name);
			if (optarg)
				printf (" with arg %s", optarg);
			printf ("\n");
			break;
		case 'c':
			if(data->mode)
				goto failure;

			data->mode = MODE_CLIENT;
			break;
		case 'd':
			snprintf(data->ipv4_dest, sizeof(data->ipv4_dest), "%s",
			         optarg);
			break;
		case 'i':
			snprintf(data->eth_if, sizeof(data->eth_if), "%s",
			         optarg);
			break;
		case 's':
			if(data->mode)
				goto failure;

			data->mode = MODE_SERVER;
			break;
		case 'v':
			data->vlan = atoi(optarg);
			break;
		default:
			printf("FILE: %s, FUNC: %s, LINE: %d\n", __FILE__, __func__, __LINE__);
			goto failure;
		}
	}

	if (optind < argc)
		goto failure;

	return 0;
failure:
	print_help(argv[0]);
	return -1;
}

static int validate_params(char *filename, struct vlan_data *data)
{
	int ret = 0;
	if(MODE_NONE == data->mode) {
		printf("Error: No mode set\n");
		ret = 1;
	}

	if(MODE_CLIENT == data->mode && strlen(data->ipv4_dest) < 1) {
		printf("Error: No destination ip address set\n");
		ret = 1;
	}

	if(strlen(data->eth_if) < 1) {
		printf("Error: No network interface set\n");
		ret = 1;
	}

	if(find_eth_if(data->eth_if)) {
		printf("Error: Invalid interface set\n");
		printf("Available:\n");
		list_eth_if(data->eth_if);
		ret = 1;
	}

	if(0 == data->vlan)
		printf("Warning: no vlan tag set\n");


	if(ret)
		print_help(filename);


	return ret;
}

static int init(struct vlan_data *data)
{
	int ret;
	char errbuf[PCAP_ERRBUF_SIZE];

	// Register signals
	signal(SIGINT, signal_handler);

	data->pcap_handle = pcap_create(data->eth_if, errbuf);
	if(!data->pcap_handle) {
		printf("Error: %s\n", errbuf);
		return 1;
	}

	ret = pcap_set_timeout(data->pcap_handle, PCAP_TIMEOUT);
	if(ret) {
		printf("Error setting timeout\n");
		return ret;
	}

	ret = pcap_activate(data->pcap_handle);
	if(ret)
		printf("Error: %s\n", pcap_statustostr(ret));

	return ret;
}

static int main_client(struct vlan_data *data)
{
	return 0;
}

static int main_server(struct vlan_data *data)
{
	struct pcap_pkthdr *pkt_header;
	const u_char *pkt_data;
	int ret;

	while(!data->exit) {
		ret = pcap_next_ex(data->pcap_handle, &pkt_header, &pkt_data);

		/* error reading packet */
		if(1 != ret) {
			printf("ERROR\n");
			return 1;
		}
		printf("pkt_header->len: %d\n", pkt_header->len);
		print_eth_header(pkt_data);
		print_ipv4_header(pkt_data);
	}
	return 0;

}

static int main_vlan(struct vlan_data *data)
{
	if(MODE_CLIENT == data->mode)
		return main_client(data);

	return main_server(data);
}

static void cleanup(struct vlan_data *data)
{
	pcap_close(data->pcap_handle);

}

int main(int argc, char *argv[])
{
	int ret;

	ret = get_params(argc, argv, &data);
	if(ret)
		return ret;

	ret = validate_params(argv[0], &data);
	if(ret)
		return ret;

	ret = init(&data);
	if(!ret)
		ret = main_vlan(&data);

	cleanup(&data);
	return ret;
}
