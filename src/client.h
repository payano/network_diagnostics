#pragma once

struct tester_params;

int  client_init(struct tester_params *data);
int  client_main(struct tester_params *data);
void client_cleanup(struct tester_params *data);
