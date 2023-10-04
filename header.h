#ifndef PARSING_H
#define PARSING_H

#include <stdint.h>

struct ethernet_header{
    uint8_t dhost[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    uint8_t shost[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint16_t type = 0x0608; // little endian
} __attribute__ ((__packed__));

struct arp_header{
    uint16_t h_type = 0x0100;
    uint16_t p_type = 0x0008; // little endian
    uint8_t h_size = 6;
    uint8_t p_size = 4;
    uint16_t op = 0x0100;
    uint8_t sha[6] = {0,}; //my mac
    uint8_t sip[4] = {0,}; //my IP
    uint8_t dha[6] = {0,}; //00:00:00:00:00:00
    uint8_t dip[4] = {0,}; //scanning target IP
} __attribute__ ((__packed__));


struct ARP_Packet{
    struct ethernet_header ether;
    struct arp_header arp;
    //uint8_t padding[18] = {0,};
} __attribute__ ((__packed__));

short dump_ethernet_header(struct ethernet_header *ethernet_header);
void dump_arp_header(struct arp_header *arp_header);

#endif // PARSING_H
