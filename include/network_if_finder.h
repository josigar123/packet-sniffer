#ifndef NETWORK_IF_FINDER
#define NETWORK_IF_FINDER

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <bsd/string.h>
#include <stdint.h>
#include <string.h>
#include "./include/types_and_errors.h"

#define MAX_NETWORK_IF_LEN 256

int handle_interface_choice(char** network_if);
pcap_if_t *find_and_display_network_interfaces(char err_buf[]);

#endif // NETWORK_IF_FINDER