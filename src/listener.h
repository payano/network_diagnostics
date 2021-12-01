#pragma once

struct tester_params;

int  listener_init(struct tester_params *data);
int  listener_main(struct tester_params *data);
void listener_cleanup(struct tester_params *data);
