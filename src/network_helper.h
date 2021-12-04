#pragma once

struct test_packet;
struct timespec;

int network_helper_init_packet(struct test_packet *packet);
void network_helper_print_packet(struct test_packet *packet);
int network_helper_compare(struct timespec *ts1, uint64_t *result);

int network_helper_find_eth_if(const char *);
void network_helper_print_eth_ifs();
