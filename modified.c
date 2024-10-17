#include <pcap.h>
#include <stdio.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/ethernet.h>       //need to change for mac os

int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    const unsigned char *packet;
    struct pcap_pkthdr header;
    struct ip *ip_header;   //iphdr was not recognized by mac os
    int packet_count = 0;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pcap file>\n", argv[0]);
        return 1;
    }

    handle = pcap_open_offline(argv[1], errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening pcap file: %s\n", errbuf);
        return 1;
    }

    while ((packet = pcap_next(handle, &header)) != NULL) {
        ip_header = (struct ip*)(packet + sizeof(struct ether_header)); 
        //changed to ether_header because ethhdr was not recognized by mac os
        printf("Packet %d: IP destination address: %s\n", ++packet_count, inet_ntoa(ip_header->ip_dst));
        // Changed bdcause there is no memeber named 'daddr' in 'struct ip'
        //Also we want to get the destination ip which you can get by doing ip_header->ip_dst
    }

    pcap_close(handle);
    return 0;
}