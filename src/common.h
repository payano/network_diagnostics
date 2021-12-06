#pragma once

#include <stdint.h>

#define IPV4_ADDR_LEN 16
#define PCAP_TIMEOUT 100
#define IFNAMESZ 16

#define _htobe16(value) (((value >> 8) & 0xFF) | ((value << 8) & 0xFF00))
#define _htobe32(value) (((value & 0xFF) << 24) | ((value & 0xFF00) << 8) | ((value & 0xFF0000) >> 8) | ((value & 0xFF000000) >> 24))

#define ETHER_TYPE_IPV4 0x0800
#define ETHER_TYPE_IPV6 0x08DD

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
	char eth_if[IFNAMESZ];
	int vlan;
	enum PROTO eth_proto;
	enum MODE mode;
	int port;
	struct mode_specific *specific;
	volatile int exit_program;
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

struct ipv4_tcp_header {
	uint16_t src_port;
	uint16_t dst_port;
	uint32_t seq_nr;
	uint32_t ack;
	uint16_t reserved:4; /* data_offset and reserved are htobe16 fixing here */
	uint16_t data_offset:4;
};

struct ipv4_udp_header {
	uint16_t src_port;
	uint16_t dst_port;
	uint16_t length;
	uint16_t checksum;
};

#define HEADER_RESP_SERVER 0xBE01
#define HEADER_RESP_CLIENT 0xBE02
#define HEADER_VERSION 0x1234
struct test_header {
	uint16_t type;
	uint16_t version;
};

struct test_packet {
	struct test_header hdr;
	uint64_t ts_sec;
	uint64_t ts_nsec;
};
