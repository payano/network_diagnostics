#pragma once

#include <stdint.h>

#define IPV4_ADDR_LEN 16
#define INTERFACE_LEN 20
#define PCAP_TIMEOUT 100

struct mode_specific;

enum MODE {
	MODE_NONE = 0,
	MODE_RECEIVER,
	MODE_CLIENT,
	MODE_LISTENER
};

enum PROTO {
	PROTO_NONE = 0,
	PROTO_TCP,
	PROTO_UDP
};

struct tester_params {
	char ipv4_dst_str[IPV4_ADDR_LEN];
	uint32_t ipv4_dst_int;
	char ipv4_src_str[IPV4_ADDR_LEN];
	uint32_t ipv4_src_int;
	char eth_if[INTERFACE_LEN];
	int vlan;
	enum PROTO eth_proto;
	enum MODE mode;
	int port;
	struct mode_specific *specific;
	int exit_program;
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
	uint32_t ttl:8;
	uint32_t protocol:8;
	uint32_t hdr_checksum:16;
	uint32_t src_address:32;
	uint32_t dest_address:32;
};


