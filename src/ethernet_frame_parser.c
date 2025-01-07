#include "./include/ethernet_frame_parser.h"

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
            exit(EXIT_FAILURE);
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
    if(frame != NULL){
        if(frame->payload != NULL){
            free(frame->payload);
        }
        free(frame);
    }else{
        fprintf(stderr, "free_frame: frame is NULL\n");
        exit(EXIT_FAILURE);
    }
    
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