#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <bsd/string.h>
#include <stdint.h>
#include <string.h>

#include "../include/types_and_errors.h"
#include "../include/ethernet_frame_parser.h"
#include "../include/ip_packet_parser.h"
#include "../include/network_if_finder.h"

void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);

int main(void){

    char err_buf[PCAP_ERRBUF_SIZE];

    if(pcap_init(0, err_buf) != 0){
        printf("Error: %s\n", err_buf);
        return PCAP_ERROR;
    }
    
    pcap_if_t* alldevsp = find_and_display_network_interfaces(err_buf);

    char* network_if;
    if(handle_interface_choice(&network_if) != INTERFACE_READ_SUCCESS){
        fprintf(stderr, "in main -> handle_interface_choice: failed reading user input\n");
        return INTERFACE_READ_FAILURE;
    }

    pcap_t* handle = pcap_create(network_if, err_buf);
    if(handle == NULL){
        printf("Error: %s\n", err_buf);
        pcap_close(handle);
        return PCAP_ERROR;
    }

    if(pcap_activate(handle) != 0){
        printf("Error: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        pcap_freealldevs(alldevsp);
        return PCAP_ERROR;
    }

    printf("Capturing packages on interface: %s\n", network_if);

    const u_char* data;
    struct pcap_pkthdr header;
    if(pcap_loop(handle, 0, packet_handler, NULL) < 0){
        fprintf(stderr, "Error: %s\n", pcap_geterr(handle));
        return PCAP_ERROR;
    }

    pcap_freealldevs(alldevsp);
    pcap_close(handle);
    free(network_if);
    return 0;
}

void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes){

    printf("Packet captured:\n");
        printf("  Timestamp: %ld.%06ld seconds\n", h->ts.tv_sec, h->ts.tv_usec);
        printf("  Captured Length: %u bytes\n", h->caplen);
        printf("  Original Length: %u bytes\n", h->len);

        /*
        printf("  Packet Data:\n");
        for (uint32_t i = 0; i < h->caplen; i++) {
            printf("%02X ", bytes[i]);
            if ((i + 1) % 16 == 0) printf("\n");
        }
        printf("\n\n");
        */

        ethernet_frame_t *frame = parse_ethernet_frame(bytes, h->len);
        display_frame(frame, 0);
        int ip_type = is_ipv4_or_ipv6(frame->payload);
        if(ip_type == IPV4){
            ipv4_datagram_t *datagram = parse_ipv4_datagram(frame->payload, 0);
            display_ipv4_datagram(datagram, 0);
            free_ipv4_datagram(datagram);
        }else if(ip_type == IPV6){
            ipv6_datagram_t *datagram = parse_ipv6_datagram(frame->payload);
        }else{
            fprintf(stderr, "packet_handler: invalid ip_type: %d\n", ip_type);
        }
        
        free_frame(frame);
}
