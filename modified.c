#include <pcap.h>
#include <stdio.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/ethernet.h>

int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    const unsigned char *packet;
    struct pcap_pkthdr header;
    struct ip *ip_header;
    int packet_count = 0;
    int last_octet_count[256]; //octet values range from 0 to 255 so we need this array to keep track of occurences

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
        uint32_t dst_ip = ntohl(ip_header->ip_dst.s_addr); // Convert the destination IP to host byte order
        int last_octet = dst_ip & 0xFF; // Get the last octet from the destination IP
        last_octet_count[last_octet]++; // Increment the count for the current last octet
    }

    pcap_close(handle);
    for (int i = 0; i < 256; i++) {
        if (last_octet_count[i] > 0) {
            printf("Last octet %d: %d \n", i, last_octet_count[i]); //print the number of occurences for each octet
        }
    }

    return 0;
}