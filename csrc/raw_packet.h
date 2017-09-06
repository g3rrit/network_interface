#ifndef RAW_PACKET_H
#define RAW_PACKET_H

unsigned short csum(unsigned short *ptr,int nbytes);

int send_rpacket();

#endif

