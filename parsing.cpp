#include <stdio.h>
#include "parsing.h"

short dump_ethernet_header(struct ethernet_header *ethernet_header){
    unsigned char *da = ethernet_header->dhost;
    unsigned char *sa = ethernet_header->shost;
    unsigned short type = ethernet_header->type;
    //printf("---------------------------------------------------------\n");
    //printf("[Ethernet Packet]\n");
    //printf("Destination MAC Address : %02x:%02x:%02x:%02x:%02x:%02x\n", da[0], da[1], da[2], da[3], da[4], da[5]);
    //printf("Source MAC Address : %02x:%02x:%02x:%02x:%02x:%02x\n", sa[0], sa[1], sa[2], sa[3], sa[4], sa[5]);
    //printf("Ethernet Type : 0x%04x\n", htons(type));
    return type;
}

void dump_arp_header(struct arp_header *arp_header){
    unsigned char *sha = arp_header->sha;
    unsigned char *sip = arp_header->sip;
    unsigned char *dha = arp_header->dha;
    unsigned char *dip = arp_header->dip;
    int opcode = arp_header->op/256;    //request 01 00 reply 02 00

    //if(opcode == 1)printf("[ARP Packet : Request]\n");
    if(opcode == 2) {
        printf("---------------------------------------------------------\n");
        printf("[ARP Packet : Reply]\n");
        printf("Source MAC Address : %02x:%02x:%02x:%02x:%02x:%02x\n",sha[0], sha[1], sha[2], sha[3], sha[4], sha[5]);
        printf("Source IP Address : %d.%d.%d.%d\n",sip[0], sip[1], sip[2], sip[3]);
        printf("Target MAC Address : %02x:%02x:%02x:%02x:%02x:%02x\n",dha[0], dha[1], dha[2], dha[3], dha[4], dha[5]);
        printf("Target IP Address : %d.%d.%d.%d\n",dip[0], dip[1], dip[2], dip[3]);

    }
}

