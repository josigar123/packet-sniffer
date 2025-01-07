#include "../include/ip_packet_parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <bsd/string.h>
#include <stdint.h>
#include <string.h>

// GENERAL FUNCTIONS
int is_ipv4_or_ipv6(const u_char *packet){

    uint8_t version;
    memcpy(&version, packet, 1);
    uint8_t ip_version = (version >> 4) & 0x0F;
    
    if(ip_version == 4){
        return IPV4;
    }

    if(ip_version == 6){
        return IPV6;
    }

    fprintf(stderr, "check_if_ipv4_or_ipv6: error, something went wrong, ip_version = %d\n", ip_version);
    return ip_version;
}

// IPv4 FUNCTIONS
// Assumes packet is ipv4 header, check is  done outside of the function
ipv4_datagram_t *parse_ipv4_datagram(const u_char *frame_payload, const uint16_t packet_length){

    // Verification jic
    int version;
    if((version = is_ipv4_or_ipv6(frame_payload)) != IPV4){
        fprintf(stderr, "parse_ipv4_datagram: error, wrong packet version: %d\n", version);
        exit(EXIT_FAILURE);
    }

    ipv4_datagram_t *datagram = (ipv4_datagram_t *)malloc(sizeof(ipv4_datagram_t));

    if(datagram == NULL){
        fprintf(stderr, "parse_ipv4_header: memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    
    memcpy(&datagram->version_and_ihl, frame_payload, 1);
    memcpy(&datagram->dscp_and_ecn, frame_payload + 1, 1);

    memcpy(&datagram->total_length, frame_payload + 2, 2);
    datagram->total_length = ntohs(datagram->total_length);

    memcpy(&datagram->identification, frame_payload + 4, 2);
    datagram->identification = ntohs(datagram->identification);

    memcpy(&datagram->flags_and_fragment_offset, frame_payload + 6, 2);
    datagram->flags_and_fragment_offset = ntohs(datagram->flags_and_fragment_offset);

    memcpy(&datagram->ttl, frame_payload + 8, 1);
    memcpy(&datagram->protocol, frame_payload + 9, 1);

    memcpy(&datagram->header_checksum, frame_payload + 10, 2);
    datagram->header_checksum = ntohs(datagram->header_checksum);

    memcpy(datagram->src_addr, frame_payload + 12, 4);
    memcpy(datagram->dest_addr, frame_payload + 16, 4);

    if(!validate_total_length_ipv4(datagram->total_length)){
        fprintf(stderr, "parse_ipv4_datagram: invalid total length: %d\n", datagram->total_length);
        exit(EXIT_FAILURE);
    }

    uint8_t ihl = (datagram->version_and_ihl & 0x0F); // ihl is last 4 bits
    if(!validate_ihl(ihl)){
            fprintf(stderr, "invalid ihl value: %d\n", ihl);
            exit(EXIT_FAILURE);
        }

    if(has_options(ihl)){
        size_t options_length = (ihl - 5) * 4;
        datagram->options = (uint8_t *)malloc(options_length);
        if(datagram->options == NULL){
            fprintf(stderr, "parse_ipv4_datagram: memory allocation failed for options\n");
            exit(EXIT_FAILURE);
        }

        datagram->options_length = options_length;

        // PARSE RESTEN AV DGRAM, MED HEADER LENGDE: 20 + options_length
        size_t payload_length = datagram->total_length - 20 - options_length;
        datagram->payload = (uint8_t *)malloc(payload_length);
        if(datagram->payload == NULL){
            fprintf(stderr, "parse_ipv4_datagram: memory allocation failed for payload with options\n");
            exit(EXIT_FAILURE);
        }
    }else{ // NO OPTIONS, OBS, field will be empty

        datagram->options = NULL;
        datagram->options_length = -1;

        size_t payload_length = datagram->total_length  - 20;

        datagram->payload = (uint8_t *)malloc(payload_length);
        if(datagram->payload == NULL){
            fprintf(stderr, "parse_ipv4_datagram: memory allocation failed for payload without options\n");
            exit(EXIT_FAILURE);
        }
    }

    return datagram;
}

void display_ipv4_datagram(ipv4_datagram_t *datagram, int show_payload)
{   
        printf("\n\n_____________________\n\n");
    printf("IPv4 DGRAM:\n");
    printf("Version: %d\n", (datagram->version_and_ihl & 0xF0) >> 4);
    printf("IHL: %d (Header Length: %d bytes)\n", 
           (datagram->version_and_ihl & 0x0F), 
           (datagram->version_and_ihl & 0x0F) * 4);
    printf("DSCP: %d\n", (datagram->dscp_and_ecn & 0xFC) >> 2);
    printf("ECN: %d\n", (datagram->dscp_and_ecn & 0x03));
    printf("Total Length: %d bytes\n", datagram->total_length);
    printf("Identification: %d\n", datagram->identification);
    printf("Flags: %d\n", (datagram->flags_and_fragment_offset & 0xE000) >> 13);
    printf("Fragment Offset: %d\n", (datagram->flags_and_fragment_offset & 0x1FFF));
    printf("TTL: %d\n", datagram->ttl);
    printf("Protocol: %d\n", datagram->protocol);
    printf("Header Checksum: 0x%04X\n", datagram->header_checksum);
    printf("Source IP: %d.%d.%d.%d\n",
           datagram->src_addr[0], datagram->src_addr[1],
           datagram->src_addr[2], datagram->src_addr[3]);
    printf("Destination IP: %d.%d.%d.%d\n",
           datagram->dest_addr[0], datagram->dest_addr[1],
           datagram->dest_addr[2], datagram->dest_addr[3]);

    if (datagram->options != NULL && datagram->options_length > 0) {
        printf("Options (%zu bytes):\n", datagram->options_length);
        for (int i = 0; i < datagram->options_length; i++) {
            printf(" %02X", datagram->options[i]);
            if ((i + 1) % 16 == 0) printf("\n");
        }
        printf("\n");
    } else {
        printf("Options: None\n");
    }

    if (show_payload && datagram->payload != NULL) {
        size_t payload_length = datagram->total_length - 
                                (datagram->version_and_ihl & 0x0F) * 4;
        printf("Payload (%zu bytes):\n", payload_length);
        for (size_t i = 0; i < payload_length; i++) {
            printf(" %02X", datagram->payload[i]);
            if ((i + 1) % 16 == 0) printf("\n");
        }
        printf("\n");
    } else {
        printf("Payload: None\n");
    }

    printf("_____________________\n\n");
}

void free_ipv4_datagram(ipv4_datagram_t *datagram)
{
    if(datagram != NULL){
        if(datagram->options != NULL){
        free(datagram->options);
        }

        if(datagram->payload != NULL){
        free(datagram->payload);
        }

        free(datagram);
    }else{
        fprintf(stderr, "free_ipv4_datagram: datagram is NULL\n");
        exit(EXIT_FAILURE);
    }

}

int has_options(uint8_t ihl){
    return ihl > 5;
}

int validate_ihl(uint8_t ihl){
    return (ihl >= 5 || ihl <= 15);
}

int validate_total_length_ipv4(uint16_t total_length){
    return total_length >= 20;
}

// IPv6 FUNCTIONS
ipv6_datagram_t *parse_ipv6_datagram(const u_char * frame_payload){

    ipv6_datagram_t *datagram = (ipv6_datagram_t *)malloc(sizeof(ipv6_datagram_t));
    if(datagram == NULL){
        fprintf(stderr, "parse_ipv6_datagram: memory allocation failed\n");
        exit(EXIT_FAILURE);
    }

    int version;
    if((version = is_ipv4_or_ipv6(frame_payload)) != IPV6){
        fprintf(stderr, "parse_ipv6_datagram: error, wrong packet version: %d\n", version);
        exit(EXIT_FAILURE);
    }

    memcpy(&datagram->version_traffic_class_flow_label, frame_payload, 4);
    datagram->version_traffic_class_flow_label = ntohl(datagram->version_traffic_class_flow_label);

    memcpy(&datagram->payload_length, frame_payload + 4, 2);
    datagram->payload_length= ntohs(datagram->payload_length);

    memcpy(&datagram->next_header, frame_payload + 6, 1);
    memcpy(&datagram->hop_limit, frame_payload + 7, 1);

    memcpy(datagram->src_addr, frame_payload + 8, 16);
    memcpy(datagram->dest_addr, frame_payload + 24, 16);
}