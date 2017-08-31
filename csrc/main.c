#include"main.h"

int main(int argc, char *argv[])
{
    if(argc != 2)
    {
        fprintf(stderr, "error! usage: argv[0] protocoll\n");
        return 0;
    }
    sniff_packets(argv[1]);

    return 0;
}

bool sniff_packets(char *protocoll)
{
    int i;
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;
    const u_char *packet;
    struct pcap_pkthdr hdr;
    struct ether_header *eptr;    /* net/ethernet.h */
    struct bpf_program fp;        /* hold compiled program */
    bpf_u_int32 maskp;            /* subnet mask */
    bpf_u_int32 netp;             /* ip */

    /* Now get a device */
    dev = pcap_lookupdev(errbuf);

    if(dev == NULL) 
    {
        fprintf(stderr, "%s\n", errbuf);
        return false;
    }
    /* Get the network address and mask */
    pcap_lookupnet(dev, &netp, &maskp, errbuf);

    /* open device for reading in promiscuous mode */
    descr = pcap_open_live(dev, BUFSIZ, 1,0, errbuf);
    if(descr == NULL) 
    {
        printf("pcap_open_live(): %s\n", errbuf);
        return false;
    }

    /* Now we'll compile the filter expression*/
    if(pcap_compile(descr, &fp, protocoll, 0, netp) == -1) 
    {
        fprintf(stderr, "Error calling pcap_compile\n");
        return false;
    }

    /* set the filter */
    if(pcap_setfilter(descr, &fp) == -1) 
    {
        fprintf(stderr, "Error setting filter\n");
        return false;
    }

    /* loop for callback function */
    pcap_loop(descr, -1, data_cb, NULL);
    return true;
}

void count_cb(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
    static int count = 1;
    fprintf(stdout, "%3d, ", count);
    fflush(stdout);
    count++;
}

void data_cb(u_char *arg, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
    int i=0;
    static int count=0;

    printf("Packet Count: %d\n", ++count);    /* Number of Packets */
    printf("Recieved Packet Size: %d\n", pkthdr->len);    /* Length of header */
    printf("Payload:\n");                     /* And now the data */
    for(i=0;i<pkthdr->len;i++) 
    {
        if(isprint(packet[i]))                /* Check if the packet data is printable */
            printf("%c ",packet[i]);          /* Print it */
        else
            printf(" . ",packet[i]);          /* If not print a . */
        if((i%16==0 && i!=0) || i==pkthdr->len-1)
            printf("\n");
    }
}
