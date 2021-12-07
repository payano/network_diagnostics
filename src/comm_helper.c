#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/ether.h>

#include <time.h>

#include "print.h"
#include "common.h"
#include "network_helper.h"
#include "comm_helper.h"

struct comm_data {
	int socket;
	struct sockaddr_in sock_addr;
	struct sockaddr_in sock_other;
	struct test_packet packet;
	int tcp_clientfd;
	int ret;
	int comm_len;
	socklen_t addr_size;

	/* For clients to get the RTT time*/
	struct timespec ts;
};

struct mode_specific {
	int (*init)(struct tester_params *data);
	int (*recv)(struct comm_data *comm);
	int (*send)(struct comm_data *comm);
	int (*end_comm)(struct comm_data *comm); /* close connection TCP */

	struct comm_data comm;

};

/* HANDLER */
static int handle_recv(struct comm_data *comm, struct sockaddr_in *sock)
{
	if(sizeof(comm->packet) != comm->comm_len)
		return 1;

	/* check if there is a correct packet*/
	if(network_helper_valid_hdr_type(comm->packet.hdr.type) ||
		network_helper_valid_hdr_version(comm->packet.hdr.version)) {
		printf("Wrong packet arrived...\n");
		return 1;
	}

	struct timespec ts;
	if (clock_gettime(CLOCK_REALTIME, &ts) == -1) {
		perror("clock_gettime");
		return EXIT_FAILURE;
	}

	printf("Packet information [\n");

	ts.tv_sec -= comm->packet.ts_sec;
	ts.tv_nsec -= comm->packet.ts_nsec;
	float sec = (ts.tv_sec - comm->packet.ts_sec) +
		((ts.tv_nsec - comm->packet.ts_nsec)* 1e-9);

	printf("  from: %s:%d\n", inet_ntoa(sock->sin_addr),
	       ntohs(sock->sin_port));
	printf("  type: %s\n", get_test_packet_type(comm->packet.hdr.type));
	printf("  version: %s\n",
	       get_test_packet_version(comm->packet.hdr.version));
	printf("  delay[s]: %f [timestamp from client and server](not reliable)\n", sec);
	printf("]\n");
	if(HEADER_RESP_SERVER == comm->packet.hdr.type) {
		struct timespec time_end;
		if(network_helper_get_time(&time_end)) return 1;
		time_end.tv_sec -= ts.tv_sec;
		time_end.tv_nsec -= ts.tv_nsec;
		float sec = time_end.tv_sec + (time_end.tv_nsec * 1e-9);
		printf("Round tip delay delay[s]: %f\n", sec);
	}
	return 0;
}

static void handle_send(struct test_packet *packet, enum MODE mode,
                        struct timespec *ts)
{
	uint16_t hdr_type = mode ==
		MODE_CLIENT ? HEADER_RESP_CLIENT : HEADER_RESP_SERVER;
	network_helper_init_packet(packet, hdr_type, ts);
}

static int get_ipv4_payload(uint8_t *ipv4_hdr, uint8_t **payload)
{
	(void)payload;
	struct ipv4_header *header;
	struct ipv4_tcp_header *tcp;
	int offset;
	header = (struct ipv4_header *)ipv4_hdr;
	switch(header->protocol) {
	case 0x06:
		tcp = (struct ipv4_tcp_header *)(ipv4_hdr + sizeof(*header));
		offset = sizeof(*header) + tcp->data_offset * 4;
		*payload = ipv4_hdr;
		*payload += offset;
		return offset;
	case 0x11:
		offset = sizeof(*header) + sizeof(struct ipv4_udp_header);
		*payload = (uint8_t*)(ipv4_hdr + offset);
		return offset;
	default:
		*payload = NULL;
		return 0;
	}
}

static void handle_recv_raw(uint8_t *data, int sz)
{
	uint8_t *payload = NULL;
	/* mac dst[6] + mac src[6] + ethertype[2]*/
	int hdr_sz = 6 + 6 + 2;
	uint8_t *ipv4;

	ipv4 = &data[14];
	if(network_helper_vlan_found(&data[12])) {
		/* + vlan[4]*/
		ipv4 += 4;
		hdr_sz += 4;
	}

	int offset_sz = get_ipv4_payload(ipv4, &payload);
	if(0 == offset_sz)
		return;

	int min_sz = offset_sz + sizeof(struct test_packet);
	if(sz < min_sz) {
		return;
	}

	struct test_packet *packet = (struct test_packet *)payload;

	if(network_helper_valid_hdr_type(packet->hdr.type) ||
		network_helper_valid_hdr_version(packet->hdr.version)) {
		return;
	}

	print_mac_dst_src(data);
	print_ipv4_header(ipv4);
	print_l4_header(ipv4);

	struct timespec ts;
	if (clock_gettime(CLOCK_REALTIME, &ts) == -1) {
		perror("clock_gettime");
		return;
	}

	ts.tv_sec -= packet->ts_sec;
	ts.tv_nsec -= packet->ts_nsec;
	float sec = ts.tv_sec + (ts.tv_nsec * 1e-9);

	printf("   Packet information [\n");
	printf("    type: %s\n", get_test_packet_type(packet->hdr.type));
	printf("    version: %s\n",
	       get_test_packet_version(packet->hdr.version));
	printf("    delay[s]: %f [timestamp from sender and listener](not reliable)\n", sec);
	printf("   ]\n");
}

/* INIT */
static int common_server_init(struct tester_params *data, int sock_type,
                              int ipproto)
{
	int ret;
	int so_reuseaddr = 1;

	data->specific->comm.socket = socket(AF_INET, sock_type, ipproto);
	if(-1 == data->specific->comm.socket) {
		perror("socket");
		return 1;
	}

	ret = setsockopt(data->specific->comm.socket, SOL_SOCKET, SO_REUSEADDR,
	                 &so_reuseaddr, sizeof(so_reuseaddr));
	if (-1 == ret) {
		perror("setsockopt SO_REUSEADDR fail");
		return 1;
	}

	data->specific->comm.sock_addr.sin_family = AF_INET;
	data->specific->comm.sock_addr.sin_port = htons(data->port);
	data->specific->comm.sock_addr.sin_addr.s_addr = htonl(data->ipv4_src_int);
	data->specific->comm.addr_size = sizeof(data->specific->comm.sock_other);

	ret = bind(data->specific->comm.socket,
	           (struct sockaddr*)&data->specific->comm.sock_addr,
	           data->specific->comm.addr_size);
	if(ret) {
		perror("bind");
		return 1;
	}

	return 0;
}

static int common_client_init(struct tester_params *data, int sock_type,
                              int ipproto)
{
	data->specific->comm.socket = socket(AF_INET, sock_type, ipproto);
	if(-1 == data->specific->comm.socket) {
		perror("socket");
		return 1;
	}

	data->specific->comm.sock_addr.sin_family = AF_INET;
	data->specific->comm.sock_addr.sin_port = htons(data->port);
	data->specific->comm.sock_addr.sin_addr.s_addr = htonl(data->ipv4_dst_int);
	data->specific->comm.addr_size = sizeof(data->specific->comm.sock_addr);

	return 0;
}

int raw_init(struct tester_params *data)
{
	struct ifreq ifr;
	struct sockaddr_ll sa = {0};
	int ret = 0;

	data->specific->comm.socket = socket(PF_PACKET, SOCK_RAW,
	                                     htons(ETH_P_ALL));

	if(-1 == data->specific->comm.socket) {
		perror("socket SOCK_RAW");
		return 1;
	}

	ret = setsockopt(data->specific->comm.socket, SOL_SOCKET,
	                 SO_BINDTODEVICE, (void *)&ifr, sizeof(ifr));
	if(ret) {
		perror("setsockopt SO_BINDTODEVICE");
		return 1;
	}

	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", data->eth_if);
	ret = ioctl(data->specific->comm.socket, SIOCGIFINDEX, &ifr);
	if(ret) {
		perror("ioctl");
		return 1;
	}

	sa.sll_family = PF_PACKET;
	sa.sll_ifindex = ifr.ifr_ifindex;
	sa.sll_pkttype = PACKET_HOST;

	ret = bind(data->specific->comm.socket, (const struct sockaddr *)&sa,
	           sizeof(sa));
	if(ret) {
		perror("bind");
		return 1;
	}
	return 0;
}


/* TCP STUFF */
static int tcp_server_init(struct tester_params *data)
{
	int ret;

	ret = common_server_init(data, SOCK_STREAM, IPPROTO_TCP);
	if(ret)
		return ret;

	ret = listen(data->specific->comm.socket, 1);
	if(ret) {
		perror("listen");
		return 1;
	}
	return 0;
}

static int udp_server_init(struct tester_params *data)
{
	return common_server_init(data, SOCK_DGRAM, IPPROTO_UDP);
}

static int tcp_client_init(struct tester_params *data)
{
	int ret;

	ret = common_client_init(data, SOCK_STREAM, IPPROTO_TCP);
	if(ret)
		return ret;

	ret = connect(data->specific->comm.socket,
	              (struct sockaddr *) &data->specific->comm.sock_addr,
	              data->specific->comm.addr_size);
	if(ret) {
		perror("connect");
		return 1;
	}
	return 0;
}

static int udp_client_init(struct tester_params *data)
{
	return common_client_init(data, SOCK_DGRAM, IPPROTO_UDP);
}

/* RECV */
static int tcp_server_recv(struct comm_data *comm)
{
	comm->tcp_clientfd = accept(comm->socket,
	                            (struct sockaddr *)&comm->sock_other,
	                            &comm->addr_size);
	printf("Waiting for data...\n");

	comm->comm_len = recv(comm->tcp_clientfd,
	                      &comm->packet,
	                      sizeof(comm->packet),
	                          0);
	if(comm->comm_len < 1) {
		printf("Connection closed.\n");
		close(comm->tcp_clientfd);
		return 1;
	};

	return handle_recv(comm, &comm->sock_other);
}

static int udp_server_recv(struct comm_data *comm)
{
	printf("Waiting for data...\n");
	comm->comm_len = recvfrom(comm->socket, &comm->packet,
	                          sizeof(comm->packet), 0,
	                          (struct sockaddr *) &comm->sock_other,
	                          &comm->addr_size);
	if(comm->comm_len < 0) {
		printf("Shutdown...\n");
		return 1;
	}

	return handle_recv(comm, &comm->sock_other);
}

static int tcp_client_recv(struct comm_data *comm)
{
	printf("Waiting for data...\n");
	comm->comm_len = recv(comm->socket, &comm->packet,
	                      sizeof(comm->packet), 0);
	if(comm->comm_len < 1) {
		printf("Connection closed.\n");
		close(comm->socket);
		return 1;
	};

	return handle_recv(comm, &comm->sock_addr);
}

static int udp_client_recv(struct comm_data *comm)
{
	printf("Waiting for data...\n");

	comm->comm_len = recvfrom(comm->socket, &comm->packet,
	                          sizeof(comm->packet), 0,
	                          (struct sockaddr *) &comm->sock_other,
	                          &comm->addr_size);
	if(comm->comm_len < 0) {
		printf("Shutdown...\n");
		return 1;
	}

	return handle_recv(comm, &comm->sock_other);
}

static int raw_recv(struct comm_data *comm)
{
	uint8_t rbuff[1024];
	int rx = recv(comm->socket, rbuff, sizeof(rbuff), 0);
	handle_recv_raw(rbuff, rx);
	return 0;
}

/* SEND */
static int tcp_server_send(struct comm_data *comm)
{
	handle_send(&comm->packet, MODE_LISTENER, NULL);

	comm->comm_len = send(comm->tcp_clientfd, &comm->packet,
	                      sizeof(comm->packet), 0);
	if(comm->comm_len < 0) {
		perror("sendto()");
		/* need to cleanup here...*/
		return 1;
	}
	return 0;
}

static int udp_server_send(struct comm_data *comm)
{
	handle_send(&comm->packet, MODE_LISTENER, NULL);

	comm->comm_len = sendto(comm->socket, &comm->packet,
	                        sizeof(comm->packet), 0,
	                        (struct sockaddr*) &comm->sock_other,
	                        comm->addr_size);
	if(comm->comm_len < 0) {
		perror("sendto()");
		/* need to cleanup here...*/
		return 1;
	}
	return 0;
}

static int tcp_client_send(struct comm_data *comm)
{
	network_helper_get_time(&comm->ts);
	handle_send(&comm->packet, MODE_CLIENT, &comm->ts);

	comm->comm_len = send(comm->socket, &comm->packet,
	                      sizeof(comm->packet), 0);
	if(comm->comm_len < 0) {
		perror("sendto()");
		/* need to cleanup here...*/
		return 1;
	}

	return 0;
}

static int udp_client_send(struct comm_data *comm)
{
	network_helper_get_time(&comm->ts);
	handle_send(&comm->packet, MODE_CLIENT, &comm->ts);

	comm->comm_len = sendto(comm->socket, &comm->packet,
	                        sizeof(comm->packet), 0,
	                        (struct sockaddr *) &comm->sock_addr,
	                        comm->addr_size);

	if(-1 == comm->comm_len)
	{
		perror("sendto()");
		return 1;
	}
	return 0;
}

/* END COMM */
static int tcp_server_end_comm(struct comm_data *comm)
{
	return close(comm->tcp_clientfd);
}


int comm_helper_init(struct tester_params *data)
{
	data->specific = calloc(1, sizeof(struct mode_specific));
	if(!data->specific) {
		printf("Couldn't allocate memory.\n");
		return 1;
	}

	switch(data->mode) {
	case MODE_CLIENT:
		switch(data->eth_proto) {
		case PROTO_TCP:
			data->specific->init       = tcp_client_init;
			data->specific->recv       = tcp_client_recv;
			data->specific->send       = tcp_client_send;
			data->specific->end_comm   = NULL;
			break;
		case PROTO_UDP:
			data->specific->init       = udp_client_init;
			data->specific->recv       = udp_client_recv;
			data->specific->send       = udp_client_send;
			data->specific->end_comm   = NULL;
			break;
		default: abort();
		}
		break;
	case MODE_RECEIVER:
		switch(data->eth_proto) {
		case PROTO_TCP:
			data->specific->init       = tcp_server_init;
			data->specific->recv       = tcp_server_recv;
			data->specific->send       = tcp_server_send;
			data->specific->end_comm   = tcp_server_end_comm;
			break;
		case PROTO_UDP:
			data->specific->init       = udp_server_init;
			data->specific->recv       = udp_server_recv;
			data->specific->send       = udp_server_send;
			data->specific->end_comm   = NULL;
			break;
		default: abort();
		}
		break;
	case MODE_LISTENER:
		data->specific->init       = raw_init;
		data->specific->recv       = raw_recv;
		data->specific->send       = NULL;
		data->specific->end_comm   = NULL;
		break;
	default: abort();
	}

	return data->specific->init(data);
}

int comm_helper_recv(struct tester_params *data)
{
	if(!data->specific->recv)
		return 1;

	data->specific->recv(&data->specific->comm);
	return 0;
}

int comm_helper_send(struct tester_params *data)
{
	if(!data->specific->send)
		return 1;

	data->specific->send(&data->specific->comm);
	return 0;
}

int comm_helper_close_client(struct tester_params *data)
{
	if(!data->specific->end_comm)
		return 0;

	data->specific->end_comm(&data->specific->comm);
	return 0;
}

int comm_helper_cleanup(struct tester_params *data)
{
	close(data->specific->comm.socket);
	free(data->specific);
	return 0;
}
