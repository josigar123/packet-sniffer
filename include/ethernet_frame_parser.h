#ifndef ETHERNET_FRAME_PARSER
#define ETHERNET_FRAME_PARSER

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <bsd/string.h>
#include <stdint.h>
#include <string.h>
#include "./include/types_and_errors.h"

#define MAX_PACKET_SIZE 65536
#define ETHERNET_MAX_PAYLOAD 1500
#define ETHERNET_MIN_PAYLOAD 42

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


ethernet_frame_t* parse_ethernet_frame(const u_char *packet, const uint16_t packet_length);
int is_vlan_tag_present(const u_char *packet);
int is_ether_type_or_length(const u_char *packet);
void free_frame(ethernet_frame_t *frame);
void display_frame(ethernet_frame_t *frame, int show_payload);

#endif // ETHERNET_FRAME_PARSER