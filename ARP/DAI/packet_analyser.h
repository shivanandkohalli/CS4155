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

#define FLAG_ERROR_PACKET 1
#define FLAG_NO_ERROR 2
#define FLAG_ADD_TO_LIST 3
#define FLAG_NOTICE_PACKET 4

#define REQUEST 1
#define REPLY 2




#define NO_ERROR 0
#define NOTICE_NOT_BROADCAST 1
#define NOTICE_REPLY_BROADCAST 2
#define ERROR_DESTINATION_MISMATCH 3
#define ERROR_SOURCE_MISMATCH 4
#define ERROR_IP_SPOOFING 5


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
extern void print_acl_list();
int check_ip_spoofing(unsigned char *sender_mac, unsigned char *sender_ip);
void add_to_acl_list(unsigned char *mac,unsigned char *ip);
void print_to_outputcsv(struct ether_header *eth_hdr,struct arp_header *arp_hdr, int error_type, int reason);
int check_mac_consistency(struct ether_header *eth_hdr, struct arp_header *arp_hdr);



#endif /* ANALYSIS_H_ */
