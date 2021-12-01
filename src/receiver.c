#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "common.h"
#include "receiver.h"

struct mode_specific {
	int socket;
	struct sockaddr_in sock_addr;
};

#define BUFLEN 512


int receiver_init(struct tester_params *data)
{
	int ret;
	int so_reuseaddr = 1;

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

	ret = setsockopt(data->specific->socket, SOL_SOCKET, SO_REUSEADDR,
	                 &so_reuseaddr, sizeof(so_reuseaddr));
	if (-1 == ret) {
		perror("setsockopt fail");
		return 1;
	}

	data->specific->sock_addr.sin_family = AF_INET;
	data->specific->sock_addr.sin_port = htons(data->port);
	data->specific->sock_addr.sin_addr.s_addr = htonl(data->ipv4_src_int);

	ret = bind(data->specific->socket,
	           (struct sockaddr*)&data->specific->sock_addr,
	           sizeof(data->specific->sock_addr));
	if(ret) {
		perror("bind");
		return 1;
	}

	return 0;
}

static int recv_udp(struct tester_params *data)
{
	char buf[BUFLEN];
	struct sockaddr_in si_other;
	socklen_t addr_size = sizeof(si_other);
	int comm_len;

	while(!data->exit_program)
	{
		printf("Waiting for data...");
		fflush(stdout);

		comm_len = recvfrom(data->specific->socket, buf, BUFLEN, 0,
		               (struct sockaddr *) &si_other, &addr_size);
		if(comm_len < 0) {
			printf("Shutdown...\n");
			break;
		}

		printf("Received packet from %s:%d\n",
		       inet_ntoa(si_other.sin_addr),
		       ntohs(si_other.sin_port));
		printf("Data: %s\n" , buf);

		comm_len = sendto(data->specific->socket, buf, comm_len,
			           0, (struct sockaddr*) &si_other, addr_size);
		if(comm_len < 0) {
			perror("sendto()");
			/* need to cleanup here...*/
			return 1;
		}
	}
	return 0;
}

static int recv_tcp(struct tester_params *data)
{
	char buf[BUFLEN];
	int clientfd;
	int ret;
	int comm_len;
	struct sockaddr_in si_other;
	socklen_t addr_size = sizeof(si_other);

	ret = listen(data->specific->socket, 1);
	if(ret) {
		perror("listen");
		return 1;
	}

	while(!data->exit_program)
	{
		clientfd = accept(data->specific->socket,
		                  (struct sockaddr *)&si_other,
		                  &addr_size);
		while(1) {
			printf("Waiting for data...");
			fflush(stdout);

			comm_len = recv(clientfd, buf, BUFLEN, 0);
			if(comm_len < 1) {
				printf("Connection closed.\n");
				close(clientfd);
				break;
			};
			//print details of the client/peer and the data received
			printf("Received packet from %s:%d\n",
			       inet_ntoa(si_other.sin_addr),
			       ntohs(si_other.sin_port));
			printf("Data: %s\n" , buf);

			comm_len = send(clientfd, buf, comm_len, 0);
			if(comm_len < 0) {
				perror("sendto()");
				/* need to cleanup here...*/
				return 1;
			}
		}
	}
	return 0;
}

int receiver_main(struct tester_params *data)
{
	switch(data->eth_proto) {
	case PROTO_TCP: return recv_tcp(data);
	case PROTO_UDP: return recv_udp(data);
	default:        return 1;
	}
}

void receiver_cleanup(struct tester_params *data)
{
	close(data->specific->socket);
	free(data->specific);
}
