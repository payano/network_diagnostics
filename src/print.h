#pragma once
enum MODE;

void print_help(char *);
char *get_ethertype(const uint16_t);
char *get_mode(const enum MODE);
char *get_ipv4_protocol(uint8_t);
void print_eth_header(struct tester_params *, const u_char *);
void print_ipv4_header(struct tester_params *, const u_char *);
void print_raw_packet(const u_char *, int);
void print_vlan_header(const uint16_t *);
