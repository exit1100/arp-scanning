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

uint8_t arpTable[256][6];
uint8_t myMac[6];
uint8_t myIp[4];

void usage() {
    printf("syntax: arp-test <interface>\n");
    printf("sample: arp-test ens33\n");
}

void myinfo(){
    FILE *fp;
    char buffer[80];
    fp = popen("ifconfig | grep -o -E '([0-9A-Fa-f]{2}:){5}([0-9A-Fa-f]{2})'", "r");
    if (fp == NULL) {
        perror("popen");
        exit(1);
    }
    if (fgets(buffer, sizeof(buffer), fp) != NULL) {
        sscanf(buffer, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &myMac[0], &myMac[1], &myMac[2], &myMac[3], &myMac[4], &myMac[5]);
    }
    pclose(fp);

    fp = popen("hostname -I", "r");
    if (fp == NULL) {
        perror("popen");
        exit(1);
    }
    if (fgets(buffer, sizeof(buffer), fp) != NULL) {
        sscanf(buffer, "%hhu.%hhu.%hhu.%hhu", &myIp[0], &myIp[1], &myIp[2], &myIp[3]);
    }
    pclose(fp);


}

void *sendPacket(void *dev){
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* pcap2 = pcap_open_live((char *)dev , BUFSIZ, 1, 1000, errbuf);
    if (pcap2 == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", (char *)dev, errbuf);
        exit(0);
    }
    uint8_t targetIp = 0;
    struct ARP_Packet arp_packet;


    memcpy(arp_packet.ether.shost, &myMac, 6);
    memcpy(arp_packet.arp.sha, &myMac, 6);
    memcpy(arp_packet.arp.sip, &myIp, 4);
    //for(int i=0; i<6; i++) arp_packet.ether.shost[i] = myMac[i];
    //for(int i=0; i<6; i++) arp_packet.ether.sha[i] = myMac[i];

    //arp_packet.arp.sip = {myIp[0], myIp[1], myIp[2], myIp[3]};

    while (1) {
        memcpy(arp_packet.arp.dip, &myIp, 3);
        arp_packet.arp.dip[3] = targetIp;
        if (pcap_sendpacket(pcap2, (unsigned char*)&arp_packet, sizeof(arp_packet)) != 0){
            printf("Fail sendpacket 1\n");
            exit (-1);
        }
        printf("dst IP : %d.%d.%d.%d\n", arp_packet.arp.dip[0], arp_packet.arp.dip[01], arp_packet.arp.dip[2], arp_packet.arp.dip[3]);
        if(targetIp == 255) sleep(10);
        targetIp++;
        usleep(3000);
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

    myinfo();
    //printf("my MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", myMac[0], myMac[1], myMac[2], myMac[3], myMac[4], myMac[5]);
    //printf("my IP : %d.%d.%d.%d\n", myIp[0], myIp[1], myIp[2], myIp[3]);

    pthread_t thread;
    pthread_create(&thread, 0, sendPacket, (void *) dev);

    pcap_t* pcap = pcap_open_live(dev , BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", dev, errbuf);
        return -1;
    }

    while (1) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        uint16_t parsingType = 0;

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
