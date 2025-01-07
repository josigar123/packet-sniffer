#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <bsd/string.h>
#include <stdint.h>
#include <string.h>
#include "./include/types_and_errors.h"
#include "./include/ethernet_frame_parser.h"

#define MAX_NETWORK_IF_LEN 256
#define IPV4 4
#define IPV6 6

#pragma pack(push, 1)
typedef struct {
    uint8_t version_and_ihl; // first 4 bits are version, last 4 ihl
    uint8_t dscp_and_ecn; // first 6 dscp, last 2 ecn
    uint16_t total_length; // total packet size (including ip header)
    uint16_t identification; // identify fragment groups
    uint16_t flags_and_fragment_offset; // 3 first, flags (Reserved, Dont Fragment, More Fragments), last 14, offset
    uint8_t ttl;
    uint8_t protocol; // Transport layer protocol used
    uint16_t header_checksum;
    uint8_t src_addr[4];
    uint8_t dest_addr[4];
    uint8_t *options; // variable length, based on IHL
    uint8_t *payload;
    size_t options_length; // lengs of options field: (IHL - 5) * 4
} ipv4_datagram_t;
#pragma pack(pop)

// Extend with extension header possibilities
#pragma pack(push, 1)
typedef struct {
    uint32_t version_traffic_class_flow_label; // version: 4b, traffic_class: 8b, flow_label: 20b
    uint16_t payload_length;
    uint8_t next_header;
    uint8_t hop_limit;
    uint8_t source_addr[16];
    uint8_t dest_addr[16];
    // Add extension header here (variable length, can be extractd from payload_length field)
    // also specifies transport layer protocol, no extension header is included
    // uint8_t *extension_header;
    uint8_t *payload;
} ipv6_datagram_t;
#pragma pack(pop)

int handle_interface_choice(char** network_if);
void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);
ethernet_frame_t* parse_ethernet_frame(const u_char *packet, const uint16_t packet_length);
int is_vlan_tag_present(const u_char *packet);
int is_ether_type_or_length(const u_char *packet);
void free_frame(ethernet_frame_t *frame);
void display_frame(ethernet_frame_t *frame, int show_payload);
pcap_if_t *find_and_display_network_interfaces(char err_buf[]);
ipv4_datagram_t *parse_ipv4_datagram(const u_char *frame_payload, const uint16_t packet_length);
int is_ipv4_or_ipv6(const u_char *packet);
int has_options(uint8_t ihl);
int validate_ihl(uint8_t ihl);
void free_ipv4_datagram(ipv4_datagram_t *datagram);
void display_ipv4_datagram(ipv4_datagram_t *datagram, int show_payload);
ipv6_datagram_t *parse_ipv6_datagram(const u_char * frame_payload);
int validate_total_length_ipv4(uint16_t total_length);

int main(void){

    char err_buf[PCAP_ERRBUF_SIZE];

    if(pcap_init(0, err_buf) != 0){
        printf("Error: %s\n", err_buf);
        return PCAP_ERROR;
    }

    pcap_if_t* alldevsp = find_and_display_network_interfaces(err_buf);

    char* network_if;
    if(handle_interface_choice(&network_if) != INTERFACE_READ_SUCCESS){
        fprintf(stderr, "handle_interface_choice: failed reading user input\n");
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

// TODO: WRITE FUNCTION FOR FREEING DGRAM
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

int has_options(uint8_t ihl){
    return ihl > 5;
}

int validate_ihl(uint8_t ihl){
    return (ihl >= 5 || ihl <= 15);
}

int validate_total_length_ipv4(uint16_t total_length){
    return total_length >= 20;
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

ipv6_datagram_t *parse_ipv6_datagram(const u_char * frame_payload){
}