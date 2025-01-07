#ifndef IP_PACKET_PARSER
#define IP_PACKET_PARSER

#include <arpa/inet.h>
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
#define NEXT_HEADER_LIMIT 10

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
    uint8_t src_addr[16];
    uint8_t dest_addr[16];
    // Add extension header here (variable length, can be extractd from payload_length field)
    // also specifies transport layer protocol, no extension header is included
    // uint8_t *extension_header;
    uint8_t *payload;
} ipv6_datagram_t;
#pragma pack(pop)

typedef enum {
    // extension headers
    hop_by_hop_options = 0,
    routing = 43,
    fragment = 44,
    authentication_header = 51,
    encapsulating_security_payload = 50,
    destination_options = 60,
    mobility = 135,
    host_identity_protocol = 139,

    // upper-layer protocols
    tcp = 6,
    udp = 17,
    icmp_v6 = 58,

    // special-case
    no_next_header = 59
} ipv6_next_header_t;

#pragma pack(push, 1)
typedef struct{
    uint8_t option_type;
    uint8_t option_data_len;
    uint8_t option_data[];
} option_t;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct {
    uint8_t next_header;
    uint8_t header_extension_length;
    option_t *options;
    size_t num_options;
} hop_by_hop_header_t;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct{
    uint8_t next_header;
    uint8_t header_extension_length;
    uint8_t routing_type;
    uint8_t segments_left;
    uint8_t type_specific_data[]; // length = (header_extension_length + 1) * 8
} routing_header_t;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct{
    uint8_t next_header;
    uint8_t reserved; // initialize to 0
    uint16_t fragmentoffset_res_m; // fragment offset = 13bit, res = 2 bit (set to 0), m = 1bit (1 more fragments, 0 no more fragments)
    uint32_t identification;
} fragment_header_t;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct{
    uint8_t next_header;
    uint8_t payload_len; // total ah_length = payload_len + 2
    uint16_t reserved; // init to 0
    uint32_t security_parameters_index;
    uint32_t sequence_number;
    uint32_t integrity_check_value[]; // len = (payload_len + 2) * 4 -12
} authentication_header_t;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct{
    uint32_t security_parameters_index;
    uint32_t sequence_number;
    uint8_t *payload;
    // optional padding between: uint8_t *padding
    uint8_t pad_len;
    uint8_t next_header;
} encapsulating_security_payload_header_t;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct{
    uint8_t next_header;
    uint8_t header_extension_length;
    option_t *options;
    size_t num_options;
} destination_options_header_t;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct{
    uint8_t payload_proto;
    uint8_t header_len;
    uint8_t MH_type;
    uint8_t reserved; // initialize to 0
    uint16_t checksum;
    uint8_t *message_data;

} mobility_header_t;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct{
    uint8_t next_header;
    uint8_t header_extension_len;
    uint8_t hip_type;
    uint8_t reserved;
    uint8_t *host_identity;
    size_t host_identity_len;
} host_identity_protocol_header_t;
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