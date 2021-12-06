#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "common.h"
#include "comm_helper.h"
#include "receiver.h"

int receiver_init(struct tester_params *data)
{
	return comm_helper_init(data);
}

int receiver_main(struct tester_params *data)
{
	while(!data->exit_program)
	{
		if(comm_helper_recv(data))
			return 1;

		if(comm_helper_send(data))
			return 1;

		if(comm_helper_close_client(data))
			return 1;
	}

	return 0;
}

void receiver_cleanup(struct tester_params *data)
{
	comm_helper_cleanup(data);
}
