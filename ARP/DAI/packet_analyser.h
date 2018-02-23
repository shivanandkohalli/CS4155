/*
 * analysis.h
 *
 *  Created on: 23-Feb-2018
 *      Author: shiva
 */

#ifndef ANALYSIS_H_
#define ANALYSIS_H_

#include "main.h"

#define PROTO_ARP 0x0806
#define MAC_LENGTH 6
#define IPV4_LENGTH 4
#define ARP_REQUEST 0x01
#define ARP_REPLY 0x02

#define MAX_LENGTH_ACLCONFIG_FILE 500
#define MAX_IPMAC_LENGTH 100

struct arp_header
{
        unsigned short hardware_type;
        unsigned short protocol_type;
        unsigned char hardware_len;
        unsigned char  protocol_len;
        unsigned short opcode;
        unsigned char sender_mac[MAC_LENGTH];
        unsigned char sender_ip[IPV4_LENGTH];
        unsigned char target_mac[MAC_LENGTH];
        unsigned char target_ip[IPV4_LENGTH];
};

extern void analyse_packet(int packet_length, const u_char* packet);
extern void init_packet_analyser(FILE *fp);

#endif /* ANALYSIS_H_ */
