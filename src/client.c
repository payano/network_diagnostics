#include "comm_helper.h"
#include "client.h"

int client_init(struct tester_params *data)
{
	return comm_helper_init(data);
}

int client_main(struct tester_params *data)
{
	if(comm_helper_send(data))
		return 1;
	if(comm_helper_recv(data))
		return 1;
	if(comm_helper_close_client(data))
		return 1;
	return 0;
}

void client_cleanup(struct tester_params *data)
{
	comm_helper_cleanup(data);
}

