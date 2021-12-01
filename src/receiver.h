#pragma once

struct tester_params;

int  receiver_init(struct tester_params *data);
int  receiver_main(struct tester_params *data);
void receiver_cleanup(struct tester_params *data);
