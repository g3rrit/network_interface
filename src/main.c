#header
#ifndef MAIN_H
#define MAIN_H

#endif

#source
#include"main.h"
#include"packetsniffer.h"
#include"packetsender.h"
#include"packetsnifferv2.h"
#include"raw_packet.h"
#include"stdio.h"

int main(int argc, char *argv[])
{
    if(argc >= 2)
    {
        if(strcmp(argv[1], "send") == 0)
        {
            if(argc != 3)
            {
                send_rpacket();
            }
        }
        else if(strcmp(argv[1], "sniff") == 0)
        {
            printf("pcap filter: %s\n", argv[2]);
            sniff_packets(stdout, argv[2]);
        }
        else if(strcmp(argv[1], "sniffv2") == 0)
        {
            printf("starting sniffing\n");
            //sniff_v2();
        }
    }
    else
    {
        fprintf(stderr, "error! usage: argv[0] filter\n");
    }

    return 0;
}


