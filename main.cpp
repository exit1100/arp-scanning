#include <pthread.h>
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include "header.h"

#define ETH_HEADER_OFFSET 14;

void usage() {
    printf("syntax: arp-test <interface>\n");
    printf("sample: arp-test ens33\n");
}

void myinfo(){
    char mac_address[18];
    char ip_address[20]; // IP 주소를 저장할 문자열 배열

    FILE *fp;
    char buffer[80];
    fp = popen("ifconfig | grep -o -E '([0-9A-Fa-f]{2}:){5}([0-9A-Fa-f]{2})'", "r");
    if (fp == NULL) {
        perror("popen");
        exit(1);
    }
    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        strncpy(mac_address, buffer, sizeof(mac_address));
    }

    fp = popen("hostname -I", "r");
    if (fp == NULL) {
        perror("popen");
        exit(1);
    }
    if (fgets(buffer, sizeof(buffer), fp) != NULL) strncpy(ip_address, buffer, sizeof(ip_address));
    pclose(fp);

    printf("MAC 주소: %s\n", mac_address);
    printf("IP 주소: %s\n", ip_address);

}

void *sendPacket(void *dev){
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* pcap2 = pcap_open_live((char *)dev , BUFSIZ, 1, 1000, errbuf);
    if (pcap2 == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", (char *)dev, errbuf);
        exit(0);
    }

    while (1) {
        struct ARP_Packet arp_packet;
        if (pcap_sendpacket(pcap2, (unsigned char*)&arp_packet, sizeof(arp_packet)) != 0){
            printf("Fail sendpacket 1\n");
            exit (-1);
        }
        printf("\n\n");
        usleep(1000);
    }
    pcap_close(pcap2);
    printf("Thread 2 Die!!\n");
}


int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return 0;
    }
    char * dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];

    struct ethernet_header *etherPointer;
    struct arp_header *arpPointer;

    //pthread_t thread;
    //pthread_create(&thread, 0, sendPacket, (void *) dev);

    pcap_t* pcap = pcap_open_live(dev , BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", dev, errbuf);
        return -1;
    }

    while (1) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        uint16_t parsingType = 0;
        int arpTable[256][6];

        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }
        etherPointer = (struct ethernet_header *)packet;
        parsingType = htons(etherPointer->type);
        //printf("%d\n", parsingType);
        if(parsingType==2054){  //2054 == 0x0806 -> ARP Packet
            packet += ETH_HEADER_OFFSET;
            arpPointer = (struct arp_header *)packet;

            unsigned char *sha = arpPointer->sha;
            unsigned char *sip = arpPointer->sip;
            unsigned char *dha = arpPointer->dha;
            unsigned char *dip = arpPointer->dip;
            int opcode = htons(arpPointer->op);    //request: 1, reply: 2

            //if(opcode == 1)printf("[ARP Packet : Request]\n");
            if(opcode == 2) {
                printf("---------------------------------------------------------\n");
                printf("[ARP Packet : Reply]\n");
                printf("Source MAC Address : %02x:%02x:%02x:%02x:%02x:%02x\n",sha[0], sha[1], sha[2], sha[3], sha[4], sha[5]);
                printf("Source IP Address : %d.%d.%d.%d\n",sip[0], sip[1], sip[2], sip[3]);
                printf("Target MAC Address : %02x:%02x:%02x:%02x:%02x:%02x\n",dha[0], dha[1], dha[2], dha[3], dha[4], dha[5]);
                printf("Target IP Address : %d.%d.%d.%d\n",dip[0], dip[1], dip[2], dip[3]);
                int cClass = sip[3];
                arpTable[cClass][0] = sha[0];
                arpTable[cClass][1] = sha[1];
                arpTable[cClass][2] = sha[2];
                arpTable[cClass][3] = sha[3];
                arpTable[cClass][4] = sha[4];
                arpTable[cClass][5] = sha[5];
                printf("ARP Table [%d] : %02x:%02x:%02x:%02x:%02x:%02x\n", cClass, arpTable[cClass][0], arpTable[cClass][1], arpTable[cClass][2], arpTable[cClass][3], arpTable[cClass][4], arpTable[cClass][5]);
            }
        }
    }

    pcap_close(pcap);
}
