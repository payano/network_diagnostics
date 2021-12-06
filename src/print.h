#pragma once

struct tester_params;

void print_help(char *);
char *get_ethertype(const uint16_t);
char *get_mode(const int);
char *get_ipv4_protocol(uint8_t);
void print_eth_header(struct tester_params *, const u_char *);
void print_ipv4_header(const uint8_t *);
void print_raw_packet(const u_char *, int);
void print_vlan_header(const uint16_t *);
void print_mac_dst_src(const uint8_t *);
void print_l4_header(uint8_t *);
