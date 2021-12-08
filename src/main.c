/*
 * main.c
 *
 *  Created on: Nov 30, 2021
 *      Author: evsejho
 */

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <signal.h>

#include "common.h"
#include "listener.h"
#include "client.h"
#include "receiver.h"
#include "print.h"
#include "network_helper.h"

#define VLAN_TPID 0x8100

struct tester_func {
	int (*init)(struct tester_params *data);
	int (*main)(struct tester_params *data);
	void (*cleanup)(struct tester_params *data);
};

struct tester_data {
	struct tester_params params;
	struct tester_func func;
};

static struct tester_data data;

static int validate_ipv4_octet(char *ipv4_octet)
{
	int len = strlen(ipv4_octet);
	int i;

	if(0 == len)
		return 1;
	if(len > 3)
		return 1;

	for(i = 0; i < len; ++i) {
		if(*ipv4_octet < '0' || *ipv4_octet > '9')
			return 1;

		++ipv4_octet;
	}
	return 0;

}

static int str_to_ipv4(char *data, uint32_t *addr)
{
	char *token;
	char buf[30];
	char search[] = ".";
	int shift = 24;
	*addr = 0;
	int ret;
	int counter = 0;

	strcpy(buf, data);
	/* get the first token */
	token = strtok(buf, search);

	/* walk through other tokens */
	while( token != NULL && shift >= 0) {
		ret = validate_ipv4_octet(token);
		if(ret) {
			printf("Validation of ipv4 address failed\n");
			return 1;
		}
		*addr |= atoi(token) << shift;

		++counter;
		shift -= 8;
		token = strtok(NULL, search);
	}
	if(4 != counter)
		printf("Invalid ipv4 address\n");

	return counter == 4 ? 0 : 1;
}

void signal_handler(int sig){
	(void)sig;
	/* bail out... */
	static int count = 0;
	data.params.exit_program = 1;

	if(!count++) {
		printf("Stopping...\n");
	} else {
		printf("Forcing stop...\n");
		exit(1);
	}
}

static int get_params(int argc, char *argv[], struct tester_params *data)
{
	int c = 0;

	if(argc < 2) {
		print_help(argv[0]);
		return -1;
	}

	static struct option long_options[] =
	{
		{"client",         no_argument,       0, 'c'},
		{"dest_addr_ipv4", required_argument, 0, 'd'},
		{"interface",      required_argument, 0, 'i'},
		{"listener",       no_argument,       0, 'l'},
		{"port",           no_argument,       0, 'p'},
		{"receiver",       no_argument,       0, 'r'},
		{"proto",          required_argument, 0, 't'},
		{"src_addr_ipv4",  required_argument, 0, 's'},
		{"vlan",           required_argument, 0, 'v'},
		{0, 0, 0, 0}
	};

	while (1)
	{
		/* getopt_long stores the option index here. */
		int option_index = 0;

		c = getopt_long (argc, argv, "cd:i:lp:rt:s:v:",
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
			if(data->mode) {
				printf("Mode already set to: %s\n",
				       get_mode(data->mode));
				goto failure;
			}

			data->mode = MODE_CLIENT;
			break;
		case 'd':
			snprintf(data->ipv4_dst_str, sizeof(data->ipv4_dst_str), "%s",
			         optarg);
			break;
		case 'i':
			snprintf(data->eth_if, sizeof(data->eth_if), "%s",
			         optarg);
			break;
		case 'l':
			if(data->mode) {
				printf("Mode already set to: %s\n",
				       get_mode(data->mode));
				goto failure;
			}

			data->mode = MODE_LISTENER;
			break;
		case 'p':
			data->port = atoi(optarg);
			break;
		case 'r':
			if(data->mode) {
				printf("Mode already set to: %s\n",
				       get_mode(data->mode));
				goto failure;
			}

			data->mode = MODE_RECEIVER;
			break;
		case 't':
			if(!strcmp("tcp", optarg)) {
				data->eth_proto = PROTO_TCP;
			} else if(!strcmp("udp", optarg)) {
				data->eth_proto = PROTO_UDP;
			}
			break;
		case 's':
			snprintf(data->ipv4_src_str, sizeof(data->ipv4_src_str), "%s",
			         optarg);
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

static int validate_params(char *filename, struct tester_params *data)
{
	int ret = 0;
	if(MODE_NONE == data->mode) {
		printf("Error: No mode set\n");
		ret = 1;
	}

	if(MODE_CLIENT == data->mode) {
		if(strlen(data->ipv4_dst_str) < 1) {
			printf("Error: No destination ip address set\n");
			ret = 1;
		}
		if(!data->port) {
			printf("Error: No source port set\n");
			ret = 1;
		}
	} else if(MODE_RECEIVER == data->mode) {
		if(strlen(data->ipv4_src_str) < 1) {
			printf("Error: No source ip address set\n");
			ret = 1;
		}
		if(!data->port) {
			printf("Error: No source port set\n");
			ret = 1;
		}
	}

	if(MODE_LISTENER != data->mode && PROTO_NONE == data->eth_proto) {
		printf("Error: No eth proto is set\n");
		ret = 1;

	}

	if(strlen(data->eth_if) < 1) {
		printf("Error: No network interface set\n");
		ret = 1;
	}

	if(network_helper_find_eth_if(data->eth_if)) {
		printf("Error: Invalid interface set\n");
		printf("Available:\n");
		network_helper_print_eth_ifs();
		ret = 1;

	}

	if(strlen(data->ipv4_dst_str) > 0 &&
		str_to_ipv4(data->ipv4_dst_str, &data->ipv4_dst_int)) {
		ret = 1;
	}

	if(strlen(data->ipv4_src_str) > 0 &&
		str_to_ipv4(data->ipv4_src_str, &data->ipv4_src_int)) {
		ret = 1;
	}

	if(ret)
		print_help(filename);
	else
		printf("Running as a %s\n", get_mode(data->mode));

	return ret;
}

static int common_init()
{
	// Register signals
	signal(SIGINT, signal_handler);

	return 0;
}

static int set_functions(struct tester_func *func, enum MODE mode)
{
	switch(mode){
	case MODE_CLIENT:
		func->init    = client_init;
		func->main    = client_main;
		func->cleanup = client_cleanup;
		break;
	case MODE_RECEIVER:
		func->init    = receiver_init;
		func->main    = receiver_main;
		func->cleanup = receiver_cleanup;
		break;
	case MODE_LISTENER:
		func->init    = listener_init;
		func->main    = listener_main;
		func->cleanup = listener_cleanup;
		break;
	default:
		printf("Error, unsupported mode!\n");
		return 1;
	}
	return 0;
}

int main(int argc, char *argv[])
{
	int ret;
	memset(&data, 0, sizeof(data));

	ret = get_params(argc, argv, &data.params);
	if(ret)
		return ret;

	ret = validate_params(argv[0], &data.params);
	if(ret)
		return ret;

	ret = set_functions(&data.func, data.params.mode);
	if(ret)
		return ret;

	common_init();
	ret = data.func.init(&data.params);
	if(!ret)
		ret = data.func.main(&data.params);

	data.func.cleanup(&data.params);
	return ret;
}
