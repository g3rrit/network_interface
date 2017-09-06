#include"packetsniffer.h"

FILE *sniffer_out;

bool sniff_packets(FILE *outfile, char *filterc)
{
    sniffer_out = outfile;

    int i;
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;
    const u_char *packet;
    struct pcap_pkthdr *hdr;
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
    printf("sniffing on dev: %s\n", dev);

    /* Get the network address and mask */
    pcap_lookupnet(dev, &netp, &maskp, errbuf);

    /* open device for reading in promiscuous mode */
    descr = pcap_open_live(dev, BUFSIZ, 1,10000, errbuf);
    if(descr == NULL) 
    {
        printf("pcap_open_live(): %s\n", errbuf);
        return false;
    }

    /* check wich link-layer header is provided */
    switch (pcap_datalink(descr))
    {
        case DLT_EN10MB:
            fprintf(sniffer_out,"IEEE 802.3 ETHERNET LINK-LAYER HEADER\n");
            break;
        case DLT_AX25:
            fprintf(sniffer_out,"NO LINK-LAYER HEADER PRESENDT\n");
            break;
        default:
            fprintf(sniffer_out,"LINK-LAYER HEADER TYPE: %i\n", pcap_datalink(descr));
    }

    /* Now we'll compile the filter expression*/
    if(pcap_compile(descr, &fp, filterc, 0, netp) == -1) 
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

    bool sniffing = true;
    do
    {
        int res = pcap_next_ex(descr, &hdr, &packet);
        if(res == 0)
            fprintf(sniffer_out, "packet buffer timeout expired\n");
        else if(res == -1)
            fprintf(sniffer_out, "error occured while reading packet\n");
        else if(res == -2)
            fprintf(sniffer_out, "no more packets to read from savefile\n");
        else
        {
            data_cb(NULL, hdr, packet);
        }

    }while(sniffing);

    /* loop for callback function */
    //pcap_loop(descr, -1, data_cb, NULL);
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
    fprintf(sniffer_out, "------------------------------------------\n");

    int i=0;
    static int count=0;

    fprintf(sniffer_out,"Packet Count: %d\n", ++count);    /* Number of Packets */
    fprintf(sniffer_out,"Recieved Packet Size: %d\n", pkthdr->len);    /* Length of header */
    fprintf(sniffer_out, "- - - - - - - - - - - - - - - - - -\n");

    fprintf(sniffer_out, "Payload in hex:\n");
    print_hex(pkthdr->len, packet);
    fprintf(sniffer_out, "\n");
    fprintf(sniffer_out, "- - - - - - - - - - - - - - - - - -\n");

    fprintf(sniffer_out,"Payload in ASCII:\n");                     /* And now the data */
    for(i=0;i<pkthdr->len;i++) 
    {
        if(isprint(packet[i]))                /* Check if the packet data is printable */
            fprintf(sniffer_out,"%c ",packet[i]);          /* Print it */
        else
            fprintf(sniffer_out," . ",packet[i]);          /* If not print a . */
        if((i%16==0 && i!=0) || i==pkthdr->len-1)
            fprintf(sniffer_out, "\n");
    }
    fprintf(sniffer_out, "- - - - - - - - - - - - - - - - - -\n");

    print_etherhdr(packet);
    fprintf(sniffer_out, "- - - - - - - - - - - - - - - - - -\n");

    //Get the IP Header part of this packet , excluding the ethernet header
    struct ip *iph = (struct ip*)(packet + 14); //sizeof ether header is 14

    print_iphdr(iph);
    fprintf(sniffer_out, "- - - - - - - - - - - - - - - - - -\n");
    
    struct tcphdr *tcph = (struct tcphdr*)(packet + 14 + ((iph->ip_hl) & 0x0f) * 4);

    print_tcphdr(tcph);
    fprintf(sniffer_out, "- - - - - - - - - - - - - - - - - -\n");

    switch (iph->ip_p) //Check the Protocol and do accordingly...
    {
        case 1:  //ICMP Protocol
            fprintf(sniffer_out,"ICMP PROTOCOL\n");
            //print_icmp_packet( buffer , size);
            break;

        case 2:  //IGMP Protocol
            fprintf(sniffer_out,"IGMP PROTOCOL\n");
            break;

        case 6:  //TCP Protocol
            fprintf(sniffer_out,"TCP PROTOCOL\n");
            //print_tcp_packet(buffer , size);
            break;

        case 17: //UDP Protocol
            fprintf(sniffer_out,"UDP PROTOCOL\n");
            //print_udp_packet(buffer , size);
            break;

        case 255:
            fprintf(sniffer_out, "RAW IP PROTOCOL\n");    
            break;

        default: //Some Other Protocol like ARP etc.
            fprintf(sniffer_out, "OTHER PROTOCOL\n");
            //++others;
            break;
    }
    fprintf(sniffer_out, "------------------------------------------\n");
}

void print_tcphdr(struct tcphdr *tcph)
{
    fprintf(sniffer_out, "TCP HEADER: \n");

    fprintf(sniffer_out, "SRC PORT: %d\n", tcph->th_sport);
    fprintf(sniffer_out, "DST PORT: %d\n", tcph->th_dport);
}

void print_iphdr(struct ip *iph)
{
    fprintf(sniffer_out, "IP HEADER: \n");

    fprintf(sniffer_out, "SRC ADDRESS: ");
    print_dec(4, &iph->ip_src.s_addr);
    fprintf(sniffer_out, "\n"); 

    fprintf(sniffer_out, "DST ADDRESS: ");
    print_dec(4, &iph->ip_dst.s_addr);
    fprintf(sniffer_out, "\n"); 
}

void print_etherhdr(const u_char *packet)
{
    struct ether_hdr *ehdr = packet;

    fprintf(sniffer_out, "destination mac address: ");
    print_mac(&ehdr->dest_mac);
    fprintf(sniffer_out, "\n");
    fprintf(sniffer_out, "source mac address: ");
    print_mac(&ehdr->src_mac);
    fprintf(sniffer_out, "\n");
}

void print_mac(u_char mac[6])
{
    for(int i = 0; i < 6; i++)
    {
        u_char res = mac[i] >> 4;
        res = res & 0x0f;
        fprintf(sniffer_out, "%X", res);
        res = mac[i];
        res = res & 0x0f;
        fprintf(sniffer_out, "%X", res);
        if(i != 5)
            fprintf(sniffer_out, ":");
    }
}

void print_dec(size_t const size, u_char *ptr)
{
    for(int i = 0; i < size; i++)
    {
        fprintf(sniffer_out, "%d", *ptr);
        if(i != size- 1)
            fprintf(sniffer_out, "-");
        ptr += 1;
    }
}

void print_hex(size_t const size, u_char *ptr)
{
    for(int i = 0; i < size; i++)
    {
        fprintf(sniffer_out, "%hhX", *ptr);
        if(i != size -1)
            fprintf(sniffer_out, "-");
        ptr += 1;
    }
}

//assumes little endian
void print_bits(size_t const size, void const * const ptr)
{
    unsigned char *b = (unsigned char*) ptr;
    unsigned char byte;
    int i, j;

    for (i=size-1;i>=0;i--)
    {
        for (j=7;j>=0;j--)
        {
            byte = (b[i] >> j) & 1;
            printf("%u", byte);
        }
    }
    puts("");
}
