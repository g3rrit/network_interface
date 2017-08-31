#ifndef MAIN_H
#define MAIN_H
#include<stdbool.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>

void data_cb(u_char *arg, const struct pcap_pkthdr* pkthdr, const u_char* packet);

void count_cb(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet);

bool sniff_packets(char *protocoll);

#endif

