#ifndef IP_PACKET_PARSER
#define IP_PACKET_PARSER

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <bsd/string.h>
#include <stdint.h>
#include <string.h>
#include "../include/types_and_errors.h"

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

// General functions
int is_ipv4_or_ipv6(const u_char *packet);

// IPv4 related functions
ipv4_datagram_t *parse_ipv4_datagram(const u_char *frame_payload, const uint16_t packet_length);
int has_options(uint8_t ihl);
int validate_ihl(uint8_t ihl);
void free_ipv4_datagram(ipv4_datagram_t *datagram);
void display_ipv4_datagram(ipv4_datagram_t *datagram, int show_payload);
int validate_total_length_ipv4(uint16_t total_length);

// IPv6 related functions
ipv6_datagram_t *parse_ipv6_datagram(const u_char * frame_payload);

#endif // IP_PACKET_PARSER