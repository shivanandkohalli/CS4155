/*
 * analysis.c
 *
 *  Created on: 23-Feb-2018
 *      Author: shiva
 */

#include "packet_analyser.h"
#include "file_operations.h"

unsigned char *acl_list[MAX_LENGTH_ACLCONFIG_FILE];
int acl_list_count = 0;

void analyse_packet(int packet_length, const u_char* packet)
{

	struct ether_header *eth_hdr;
	struct arp_header *arp_hdr;


	if (packet_length < sizeof(struct ether_header))
	{
		printf("Error: Ethernet header size");
		return;
	}

	eth_hdr = (struct ether_header*)packet;

	if(ntohs(eth_hdr->ether_type) != PROTO_ARP)
	{
		printf("Not an ARP packet");
		return;
	}

	// Incrementing to the next field
	packet += sizeof(struct ether_header);
	packet_length -= sizeof(struct ether_header);

	arp_hdr = (struct arp_header *)packet;
    unsigned short hardware_type;
    unsigned short protocol_type;
    unsigned char hardware_len;
    unsigned char  protocol_len;
    unsigned short opcode;
    unsigned char sender_mac[MAC_LENGTH];
    unsigned char sender_ip[IPV4_LENGTH];
    unsigned char target_mac[MAC_LENGTH];
    unsigned char target_ip[IPV4_LENGTH];
//	printf("Hardware type %d\r\n",ntohs(arp_hdr->hardware_type));
//	printf("Protocol type %x\r\n",ntohs(arp_hdr->protocol_type));
//	printf("hardware_len %d\r\n",(arp_hdr->hardware_len));
//	printf("protocol_len %d\r\n",(arp_hdr->protocol_len));
//	printf("opcode %d\r\n",ntohs(arp_hdr->opcode));

    if(find_in_acl(arp_hdr->sender_mac, arp_hdr->sender_ip))
    {
    	printf("Present in list");
    }
    else
    {
    	printf("Not present in list");
    }

	printf("\r\n\r\n\r\n");
}

int find_in_acl(unsigned char *sender_mac, unsigned char *sender_ip)
{
	int retval = TRUE;
	int i,j;
	unsigned char *mac_ip;

	for(i=0;i<acl_list_count;i++)
	{
		retval = TRUE;
		mac_ip = acl_list[i];
		for(j=0;j<4;j++)
		{
			if(mac_ip[j] != sender_ip[j]){
				retval = FALSE;
				break;
			}
		}
		if(retval == FALSE)
			continue;

		for(j=4;j<10;j++)
		{
			if(mac_ip[j] != sender_mac[j-4]){
				retval = FALSE;
				break;
			}
		}

		if(retval == TRUE)
			break;
	}

	return retval;

	//construct_macip_str(sender_mac, sender_ip, mac_ip);
}

//void construct_macip_str(sender_mac, sender_ip, mac_ip);
//{
//
//}
static void print_acl_list()
{
	int i = 0;
	int j=0;
	for(i=0;i<acl_list_count;i++){
		for(j=0;j<10;j++){
			printf("%x.",acl_list[i][j]);
		}
		printf("\r\n");
	}
}

void init_packet_analyser(FILE *fp)
{
	acl_list_count = init_access_ctrl_list(fp, acl_list);
	//print_acl_list();
}


