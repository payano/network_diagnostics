
#include <stdio.h>
#include <libgen.h>
#include <stdint.h>
#include <sys/types.h>
#include <string.h>

#include "common.h"
#include "print.h"

#define _htobe16(value) ((value >> 8) & 0xFF) | ((value << 8) & 0xFF00)

void print_help(char *filename)
{
	printf("Usage %s:\n", basename(filename));
	printf("  -c       Mode client   (sends data to server)\n");
	printf("  -r       Mode receiver (receives data from client)\n");
	printf("  -l       Mode listener (listens to data from client)\n");
	printf("  -i       Network interface to use\n");
	printf("  -d       Destination address to send data (used with -c)\n");
	printf("  -p       port number\n");
	printf("  -s       Source address to send data (used with -c)\n");
	printf("  -t       ethernet protocol (tcp or udp)\n");
	printf("  -v       vlan id\n");
}

char *get_ethertype(const uint16_t ethertype)
{
	/* Source: https://en.wikipedia.org/wiki/EtherType */
	switch(ethertype){
	case 0x0800: return "IPV4";
	case 0x86DD: return "IPV6 (UNSUPPORTED)";
	default: return "UNSUPPORTED";
	}
}

char *get_mode(const enum MODE mode)
{
	switch(mode) {
	case MODE_CLIENT:   return "Mode client";
	case MODE_RECEIVER: return "Mode receiver";
	case MODE_LISTENER: return "Mode listener";
	default:            return "Unsupported mode";
	}
}

char *get_ipv4_protocol(const uint8_t protocol)
{
	switch(protocol){
	case 0x06: return "TCP";
	case 0x11: return "UDP";
	default:   return "UNSUPPORTED IPV4 PROTOCOL";
	}
}

void print_eth_header(struct tester_params *data, const u_char *payload)
{
	const uint16_t *vlan_tpid = (const uint16_t *)&payload[12];
	const uint16_t *ethertype = (const uint16_t *)&payload[12];

	printf("ETH  header [");
	printf("dst: %02x:%02x:%02x:%02x:%02x:%02x, ",
	       payload[0], payload[1], payload[2],
	       payload[3], payload[4], payload[5]);
	printf("src: %02x:%02x:%02x:%02x:%02x:%02x, ",
	       payload[6], payload[7], payload[8],
	       payload[9], payload[10], payload[11]);

	if(data->vlan)
	{
		print_vlan_header(vlan_tpid);
		ethertype++;
	}

	printf("ethertype: %s", get_ethertype(_htobe16(*ethertype)));
	printf("]\n");
}

void print_ipv4_header(struct tester_params *data, const u_char *payload)
{
	const uint16_t *vlan_tpid = (const uint16_t *)&payload[12];
	const u_char *ip_hdr_ptr = (const u_char *)(vlan_tpid+1);
	const struct ipv4_header *header;

	if(data->vlan)
		ip_hdr_ptr = (const u_char *)(vlan_tpid+2);

	header = (struct ipv4_header*)ip_hdr_ptr;

	printf("IPV4 header [");

	printf("protocol: %s, ", get_ipv4_protocol(header->protocol));

	printf("dst: %d.", (header->dest_address )& 0xff);
	printf("%d.",      (header->dest_address >> 8)& 0xff);
	printf("%d.",      (header->dest_address >> 16)& 0xff);
	printf("%d, ",     (header->dest_address >> 24)& 0xff);

	printf("src: %d.", (header->src_address )& 0xff);
	printf("%d.",      (header->src_address >> 8)& 0xff);
	printf("%d.",      (header->src_address >> 16)& 0xff);
	printf("%d",     (header->src_address >> 24)& 0xff);

	printf("]\n");

}

void print_raw_packet(const u_char *data, int len)
{
	int i;

	for(i = 0; i < 0x10 ; ++i)
		printf("0x%02x ", i);
	printf("\n");

	for(i = 0; i < 0x10 ; ++i)
		printf("-----");

	for(i = 0; i < len ; ++i) {
		if(0 == (i % 16)) printf("\n");
		printf("0x%02x ", data[i]);
	}
	printf("\n");
}

void print_vlan_header(const uint16_t *vlan_hdr)
{
	struct vlan_tpid vlan;
	uint16_t *vlan16 = (uint16_t*)&vlan;
	memcpy(&vlan, vlan_hdr, sizeof(vlan));
	*vlan16 = _htobe16(*vlan16);
	vlan16++;
	*vlan16 = _htobe16(*vlan16);
	printf("VLAN id: %d, pcp: %d, dei: %d\n",
			vlan.vid, vlan.pcp, vlan.dei);
}
