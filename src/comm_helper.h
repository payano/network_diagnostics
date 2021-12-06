#pragma once

struct tester_params;

int comm_helper_init(struct tester_params *data);
int comm_helper_recv(struct tester_params *data);
int comm_helper_send(struct tester_params *data);
int comm_helper_close_client(struct tester_params *data);
int comm_helper_cleanup(struct tester_params *data);
