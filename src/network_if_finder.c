#include "../include/network_if_finder.h"

int handle_interface_choice(char** network_if){

    char buf[MAX_NETWORK_IF_LEN];
    printf("From the list above, choose the interface you want to capture packets from: \n");

    printf("Input: ");
    if(fgets(buf, sizeof(buf), stdin) == NULL){
        fprintf(stderr, "handle_interface_choice: failed to read input\n");
        return FGETS_ERROR;
    }

    printf("___________________________\n\n");

    size_t len = strlen(buf);
    if (len > 0 && buf[len - 1] == '\n') {
        buf[len - 1] = '\0';
    }

    *network_if = (char *)malloc(len);

    if(network_if == NULL){
        fprintf(stderr, "handle_interface_choice: memory allocation failed\n");
        return MEMORY_ALLOCATION_FAILURE;
    }

    strlcpy(*network_if, buf, MAX_NETWORK_IF_LEN); // from bsd/string.h, remove dep and use include/string.h
                                                   // and null-terminate using strncpy(2)

    return INTERFACE_READ_SUCCESS;
}

pcap_if_t *find_and_display_network_interfaces(char err_buf[]){

    pcap_if_t* alldevsp;
    if(pcap_findalldevs(&alldevsp, err_buf) != 0){
        fprintf(stderr, "%s\n", err_buf);
        pcap_freealldevs(alldevsp);
        exit(PCAP_ERROR);
    }

    printf("___________________________\n\n");
    printf("Network interfaces found:\n");

    int enumeration = 1;
    while(alldevsp != NULL){

        printf("%d: %s\n", enumeration, alldevsp->name);
        alldevsp = alldevsp->next;
        enumeration++;
    }
    printf("___________________________\n\n");

    return alldevsp;
}