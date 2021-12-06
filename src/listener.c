#include <string.h>

#include "common.h"
#include "listener.h"
#include "comm_helper.h"

int listener_init(struct tester_params *data)
{
	return comm_helper_init(data);
}

int listener_main(struct tester_params *data)
{
	while(!data->exit_program) {
		if(comm_helper_recv(data))
			return 1;
	}
	return 0;
}

void listener_cleanup(struct tester_params *data)
{
	comm_helper_cleanup(data);
}

