#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "common.h"
#include "client.h"

#define BUFLEN 512

struct mode_specific {
	int socket;
	struct sockaddr_in sock_addr;
};

int client_init(struct tester_params *data)
{
	data->specific = calloc(1, sizeof(struct mode_specific));
	if(!data->specific) {
		printf("Couldn't allocate memory.\n");
		return 1;
	}

	if(PROTO_TCP == data->eth_proto)
		data->specific->socket = socket(AF_INET, SOCK_STREAM,
		                                IPPROTO_TCP);
	else
		data->specific->socket = socket(AF_INET, SOCK_DGRAM,
		                                IPPROTO_UDP);
	if(-1 == data->specific->socket) {
		perror("socket");
		return 1;
	}

	data->specific->sock_addr.sin_family = AF_INET;
	data->specific->sock_addr.sin_port = htons(data->port);
	data->specific->sock_addr.sin_addr.s_addr = htonl(data->ipv4_dst_int);

	return 0;
}

static int send_tcp(struct tester_params *data)
{
	char buf[BUFLEN] = "TCP TEST";
	int comm_len = strlen(buf);
	int ret;

	socklen_t addr_size = sizeof(data->specific->sock_addr);

	ret = connect(data->specific->socket,
	                   (struct sockaddr *) &data->specific->sock_addr,
	                   addr_size);
	if(ret) {
		perror("connect");
		return 1;
	}
	comm_len = send(data->specific->socket, buf, comm_len, 0);
	if(comm_len < 0) {
		perror("sendto()");
		/* need to cleanup here...*/
		return 1;
	}

	return 0;
}

static int send_udp(struct tester_params *data)
{
	char message[] = "YOLO";
	int comm_len;
	socklen_t addr_size = sizeof(data->specific->sock_addr);

	comm_len = sendto(data->specific->socket, message, strlen(message), 0,
	       (struct sockaddr *) &data->specific->sock_addr, addr_size);

	if(-1 == comm_len)
	{
		perror("sendto()");
		return 1;
	}
	return 0;
}

int client_main(struct tester_params *data)
{
	switch(data->eth_proto) {
	case PROTO_TCP: return send_tcp(data);
	case PROTO_UDP: return send_udp(data);
	default:        return 1;
	}


}

void client_cleanup(struct tester_params *data)
{
	close(data->specific->socket);
	free(data->specific);
}
