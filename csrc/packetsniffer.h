#ifndef PACKETSNIFFER_H
#define PACKETSNIFFER_H
#include<stdbool.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <netinet/if_ether.h>
#include <sys/socket.h>

#ifndef __USE_BSD
#define __USE_BSD
#endif
#include <netinet/ip.h>
#ifndef __FAVOR_BSD
#define __FAVOR_BSD
#endif
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#ifndef KERNEL
#define KERNEL
#endif
#ifndef __APPLE_API_PRIVATE
#define __APPLE_API_PRIVATE
#endif
#include <netinet/in.h>
#include <net/if.h>

struct ether_hdr
{
    u_char dest_mac[6];
    u_char src_mac[6];
    u_short ether_type;
};

void data_cb(u_char *arg, const struct pcap_pkthdr* pkthdr, const u_char* packet);

void count_cb(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet);

bool sniff_packets(FILE *outfile, char *filterc);

void print_etherhdr(const u_char *packet);
void print_iphdr(struct ip *iph);
void print_tcphdr(struct tcphdr *tcph);
void print_mac(u_char mac[6]);
void print_bits(size_t const size, void const * const ptr);
void print_hex(size_t const size, u_char *ptr);
void print_dec(size_t const size, u_char *ptr);

FILE *sniffer_out;

#endif

