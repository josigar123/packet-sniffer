#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <bsd/string.h>
#include <stdint.h>
#include <string.h>

#define MAX_NETWORK_IF_LEN 256
#define MAX_PACKET_SIZE 65536
#define ETHERNET_MAX_PAYLOAD 1500
#define ETHERNET_MIN_PAYLOAD 42
#define IPV4 4
#define IPV6 6

#define FGETS_ERROR 2
#define INTERFACE_READ_SUCCESS 3
#define INTERFACE_READ_FAILURE 4
#define MEMORY_ALLOCATION_FAILURE 5

typedef unsigned char u_char;

typedef enum {
    ARP,
    IPv4,
    IPv6,
    IEE_802_1Q // VLAN tagged frame
} ether_t;

// 1 indicates presence
typedef struct {
    int vlan_tag_present;
    int frame_containts_ether_type;
}ethernet_frame_flags_t;

#pragma pack(push, 1)
typedef struct {
    uint8_t MAC_dest[6];
    uint8_t MAC_src[6];
    uint8_t vlan_tag[4]; // Optional field
    union{
        uint16_t ether_type;
        uint16_t length;
    } ether_type_or_length;
    uint8_t *payload;
    uint32_t crc_32;
    ethernet_frame_flags_t flags; // NOT IN STANDARD
    size_t payload_length; // NOT IN STANDARD
} ethernet_frame_t;
#pragma pack(pop)

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
int check_if_ipv4_or_ipv6(const u_char *packet);

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

        printf("  Packet Data:\n");
        for (uint32_t i = 0; i < h->caplen; i++) {
            printf("%02X ", bytes[i]);
            if ((i + 1) % 16 == 0) printf("\n");
        }
        printf("\n\n");

        ethernet_frame_t *frame = parse_ethernet_frame(bytes, h->len);
        display_frame(frame, 0);
        free_frame(frame);
}

ethernet_frame_t* parse_ethernet_frame(const u_char *packet, const uint16_t packet_length){

    ethernet_frame_t *frame = (ethernet_frame_t *)malloc(sizeof(ethernet_frame_t));

    if(frame == NULL){
        fprintf(stderr, "parse_ethernet_frame: memory allocation failed\n");
        exit(EXIT_FAILURE);
    }

    int vlan_tag_present = is_vlan_tag_present(packet);

    memcpy(frame->MAC_dest, packet, 6);
    memcpy(frame->MAC_src, packet + 6, 6);

    if(vlan_tag_present){

        frame->flags.vlan_tag_present = 1;
        frame->flags.frame_containts_ether_type = 1;
        memcpy(frame->vlan_tag, packet + 12, 4); // tpid and tci, 2 bytes each
        memcpy(&frame->ether_type_or_length.ether_type, packet + 16, 2); // always ether_type if tag is present

        int payload_length = packet_length - 22;

        frame->payload_length = payload_length;
        frame->payload = (uint8_t *)malloc(payload_length);
        if(frame->payload == NULL){
            fprintf(stderr, "Error: Memory allocation failed\n");
        }

        memcpy(frame->payload, packet + 18, payload_length);
        memcpy(&frame->crc_32, packet + 18 + payload_length, 4);
    }else{
        
        frame->flags.vlan_tag_present = 0;
        memset(frame->vlan_tag, 0, sizeof(frame->vlan_tag)); // Policy for validating omitted fields

        int b_ether_type = is_ether_type_or_length(packet);
        if(b_ether_type){ // Ethernet II frame
            frame->flags.frame_containts_ether_type = 1;
            memcpy(&frame->ether_type_or_length.ether_type, packet + 12, 2); // CAUTION: vlan_tag field will now be empty

            int payload_length = packet_length - 18;
            frame->payload_length = payload_length;
            frame->payload = (uint8_t *)malloc(payload_length);
            if(frame->payload == NULL){
            fprintf(stderr, "Error: Memory allocation failed\n");
            }

            memcpy(frame->payload, packet + 14, payload_length);
            memcpy(&frame->crc_32, packet + 14 + payload_length, 4);

        }else{ // IEEE 802.3 frame
            frame->flags.frame_containts_ether_type = 0;
            memcpy(&frame->ether_type_or_length.length, packet + 12, 2); // CAUTION: vlan_tag field will now be empty

            int payload_length = packet_length - 18;
            frame->payload_length = payload_length;
            frame->payload = (uint8_t *)malloc(payload_length);
            if(frame->payload == NULL){
            fprintf(stderr, "Error: Memory allocation failed\n");
            }

            memcpy(frame->payload, packet + 14, payload_length);
            memcpy(&frame->crc_32, packet + 14 + payload_length, 4);
        }
    }

    return frame;
}

int is_vlan_tag_present(const u_char *packet){
    uint16_t tpid = ntohs(*(uint16_t *)(packet + 12));
    return tpid == 0x8100;
}

// USE ONLY IF VLAN-TAG IS NOT PRESENT, OFFSET IS HARDCODED
int is_ether_type_or_length(const u_char *packet){
    uint16_t ether_type = ntohs(*(uint16_t *)(packet + 12));
    return ether_type > ETHERNET_MAX_PAYLOAD + 36;
}

void free_frame(ethernet_frame_t *frame){
    free(frame->payload);
    free(frame);
}

// Assumes a valid frame
void display_frame(ethernet_frame_t *frame, int show_payload){
    
    printf("\n\n_____________________\n\n");
    printf("ETHERNET FRAME:\n");

    printf("MAC dest: ");
    for(int i = 0; i < 6; i++){
        printf(" %02X", frame->MAC_dest[i]);
    }

    printf("\n");

    printf("MAC src: ");
    for(int i = 0; i < 6; i++){
        printf(" %02X", frame->MAC_src[i]);
    }

    if(frame->flags.vlan_tag_present){
        printf("\n");
        printf("VLAN tag:\n");
        printf("\ttpid: %02X %02X\n", frame->vlan_tag[0], frame->vlan_tag[1]);
        printf("\ttci: %02X %02X", frame->vlan_tag[2],frame->vlan_tag[3]);
    }

    if(frame->flags.frame_containts_ether_type){
        printf("\n");
        printf("Ether type: %04X", htons(frame->ether_type_or_length.ether_type));
    }else{
        printf("\n");
        printf("Length: %d", htons(frame->ether_type_or_length.length));
    }

    if(show_payload){
        printf("\nPAYLOAD:\n");
        for(int i = 0; i < frame->payload_length; i++){
            printf("%02X ", frame->payload[i]);
            if ((i + 1) % 16 == 0) printf("\n");
        }
    }

    printf("\ncrc32: %02X", frame->crc_32);

    printf("\n_____________________\n\n");
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

ipv4_datagram_t *parse_ipv4_datagram(const u_char *frame_payload, const uint16_t packet_length){

    ipv4_datagram_t *datagram = (ipv4_datagram_t *)malloc(sizeof(ipv4_datagram_t));

    if(datagram == NULL){
        fprintf(stderr, "parse_ipv4_header: memory allocation failed\n");
        exit(EXIT_FAILURE);
    }

    // PARSING LOGIC
    
    // extracting version


    return datagram;
}

int check_if_ipv4_or_ipv6(const u_char *packet){

    uint8_t version;
    memcpy(&version, packet, 1);
    uint8_t ip_version = version >> 4;
    
    if(ip_version == 4){
        return IPV4;
    }

    if(ip_version == 6){
        return IPV6;
    }

    fprintf(stderr, "check_if_ipv4_or_ipv6: error, something went wrong, ip_version = %d\n", ip_version);
    return ip_version;
}