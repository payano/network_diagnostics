#pragma once

struct test_packet;
struct timespec;

int network_helper_init_packet(struct test_packet *packet, uint16_t);
void network_helper_print_packet(struct test_packet *packet);
//int network_helper_compare(struct test_packet *, int);

int network_helper_find_eth_if(const char *);
void network_helper_print_eth_ifs();
int network_helper_vlan_found(uint8_t *);
int network_helper_valid_hdr_type(uint16_t);
int network_helper_valid_hdr_version(uint16_t);
