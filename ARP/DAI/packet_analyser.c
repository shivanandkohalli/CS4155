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
static unsigned int packet_count= 0;

struct spam_check_database spam_check_db;

void analyse_packet(int packet_length, const u_char* packet)
{

	struct ether_header *eth_hdr;
	struct arp_header *arp_hdr;

	int retval;

	packet_count++; // Increment the number of packets received

	if (packet_length < sizeof(struct ether_header))
	{
		printf("Error: Ethernet header size");
		return;
	}

	eth_hdr = (struct ether_header*)packet;

	// Even though filter is applied, just doing a sanity check
	if(ntohs(eth_hdr->ether_type) != PROTO_ARP)
	{
		printf("Not an ARP packet");
		return;
	}

	// Incrementing to the next field
	packet += sizeof(struct ether_header);
	packet_length -= sizeof(struct ether_header);

	arp_hdr = (struct arp_header *)packet;

	retval = check_ip_spoofing(arp_hdr->sender_mac,arp_hdr->sender_ip);

	if(ntohs(arp_hdr->opcode) == REPLY){
		switch(retval)
		{
		case FLAG_NO_ERROR:
			// Nothing to be done
			printf("No Error");
			break;
		case FLAG_ADD_TO_LIST:
			add_to_acl_list(arp_hdr->sender_mac,arp_hdr->sender_ip);
			printf("Add to List");
			break;
		case FLAG_ERROR_PACKET:
			//fprintf(output_ptr,"%d,0x%x,%d,%d",ntohs(arp_hdr->hardware_type),ntohs(arp_hdr->protocol_type),arp_hdr->hardware_len,arp_hdr->protocol_len);
			print_to_outputcsv(eth_hdr,arp_hdr,FLAG_ERROR_PACKET,ERROR_IP_SPOOFING);
			printf("Error packet");
			break;
		default:
			printf("Control should not come here, program error");
			break;
		}
	}

	retval = check_mac_consistency(eth_hdr,arp_hdr);
	switch(retval)
	{
	case NO_ERROR:
		// Nothing to do
		break;
	case NOTICE_NOT_BROADCAST:
		print_to_outputcsv(eth_hdr,arp_hdr,FLAG_NOTICE_PACKET,NOTICE_NOT_BROADCAST);
		break;
	case NOTICE_REPLY_BROADCAST:
		print_to_outputcsv(eth_hdr,arp_hdr,FLAG_NOTICE_PACKET,NOTICE_REPLY_BROADCAST);
		break;
	case ERROR_DESTINATION_MISMATCH:
		print_to_outputcsv(eth_hdr,arp_hdr,FLAG_ERROR_PACKET,ERROR_DESTINATION_MISMATCH);
		break;
	case ERROR_SOURCE_MISMATCH:
		print_to_outputcsv(eth_hdr,arp_hdr,FLAG_ERROR_PACKET,ERROR_SOURCE_MISMATCH);
		break;
	default:
		printf("Code Error fun:check_mac_consistency:Shouldnt reach here");
		break;
	}


	if(ntohs(arp_hdr->opcode) == ARP_REQUEST)
	{
		check_if_spamming(eth_hdr,arp_hdr);
	}
	else if(ntohs(arp_hdr->opcode) == ARP_REPLY)
	{
		if(check_ip_consistency(arp_hdr) == TRUE)
		{
			print_to_outputcsv(eth_hdr,arp_hdr,FLAG_ERROR_PACKET,ERROR_SOURCEIP_BROADCAST);
		}
	}

	printf("\r\n\r\n\r\n");
}

static int is_mac_broadcast(unsigned char *address)
{
	int i=0;
	for(i=0;i<MAC_LENGTH;i++)
	{
		if(address[i] != 0xff)
			return FALSE;
	}
	return TRUE;
}
// Checks if the source MAC at link layer is same as in the ARP request/reply
int check_mac_consistency(struct ether_header *eth_hdr, struct arp_header *arp_hdr)
{
	int i=0;
	// Check source address
	for(i=0;i<MAC_LENGTH;i++)
	{
		if(eth_hdr->ether_shost[i]!= arp_hdr->sender_mac[i])
			return ERROR_SOURCE_MISMATCH;
	}

	if(ntohs(arp_hdr->opcode) == ARP_REQUEST)
	{
		if(is_mac_broadcast(eth_hdr->ether_dhost) == TRUE)
			return NO_ERROR;
		else
			return NOTICE_NOT_BROADCAST;
	}
	else if(ntohs(arp_hdr->opcode) == ARP_REPLY)
	{
		if(is_mac_broadcast(eth_hdr->ether_dhost) == TRUE)
			return NOTICE_REPLY_BROADCAST;
		else
		{
			for(i=0;i<MAC_LENGTH;i++)
			{
				if(eth_hdr->ether_dhost[i]!= arp_hdr->target_mac[i])
					return ERROR_DESTINATION_MISMATCH;
			}
		}
	}
	return NO_ERROR;
}

int check_ip_consistency(struct arp_header *arp_hdr)
{
	unsigned char broadcast1[4] = {255,255,255,255};
	unsigned char broadcast2[4] = {0,0,0,0};

	if(check_ip_same(arp_hdr->sender_ip,broadcast1) == TRUE || check_ip_same(arp_hdr->sender_ip,broadcast2) == TRUE)
	{
		return TRUE;
	}
	return FALSE;
}
void add_to_acl_list(unsigned char *mac,unsigned char *ip)
{
	int i=0;

	acl_list[acl_list_count] = (unsigned char *)malloc(SIZEOF_MAC_IP);
	for(i=0;i<IPV4_LENGTH;i++)
		acl_list[acl_list_count][i] = ip[i];
	for(i=0;i<MAC_LENGTH;i++)
		acl_list[acl_list_count][i+IPV4_LENGTH] = mac[i];

	//increment the count of acl_list
	acl_list_count++;
}
int check_ip_same(unsigned char *ip1, unsigned char *ip2)
{
	int j=0;
	int retval = TRUE;
	for(j=0;j<IPV4_LENGTH;j++)
	{
		if(ip1[j] != ip2[j]){
			retval = FALSE;
			break;
		}
	}
	return retval;
}

static int check_mac_same(unsigned char *mac1, unsigned char *mac2)
{
	int j=0;
	int retval = TRUE;
	for(j=0;j<MAC_LENGTH;j++)
	{
		if(mac1[j] != mac2[j]){
			retval = FALSE;
			break;
		}
	}
	return retval;
}

int check_ip_spoofing(unsigned char *sender_mac, unsigned char *sender_ip)
{
	int i;
	unsigned char *mac_ip;

	for(i=0;i<acl_list_count;i++)
	{
		mac_ip = acl_list[i];


		if(check_ip_same(mac_ip, sender_ip) == FALSE)
			continue;

		// Host is pretending to be someone else, flag the packet
		if(check_mac_same(&mac_ip[IPV4_LENGTH],sender_mac) == FALSE)
		{
			return FLAG_ERROR_PACKET;
		}
		else
		{	// mac_ip is present in the ACL list, hence no error
			return FLAG_NO_ERROR;
		}
	}

	// The mac_ip is not in the list, its a new pair, needs to be added to the list
	return FLAG_ADD_TO_LIST;

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


}


void print_acl_list()
{
	int i = 0;
	int j=0;
	for(i=0;i<acl_list_count;i++){
		for(j=0;j<4;j++){
			printf("%d.",acl_list[i][j]);
		}

		for(j=4;j<10;j++){
			printf("%x.",acl_list[i][j]);
		}
		printf("\r\n");
	}
}

void init_packet_analyser(FILE *fp)
{
	acl_list_count = init_access_ctrl_list(fp, acl_list);
	init_spam_check_db();
	//print_acl_list();
}

static void print_mac(unsigned char *mac)
{
	int i=0;
	for(i=0;i<MAC_LENGTH;i++)
	{
		fprintf(output_ptr,"%x",mac[i]);
		if(i!=5)
			fprintf(output_ptr,":");
	}
	fprintf(output_ptr,",");
}
static void print_ip(unsigned char *ip)
{
	int i=0;
	for(i=0;i<IPV4_LENGTH;i++)
	{
		fprintf(output_ptr,"%d",ip[i]);
		if(i!=IPV4_LENGTH-1)
			fprintf(output_ptr,".");
	}
	fprintf(output_ptr,",");
}

static void print_eth_header(struct ether_header *eth_hdr)
{

	fprintf(output_ptr,"Packet_%d,",packet_count);
	print_mac(eth_hdr->ether_dhost);
	print_mac(eth_hdr->ether_shost);
	fprintf(output_ptr,"ARP,");

}

static void print_arp_header(struct arp_header *arp_hdr)
{
	fprintf(output_ptr,"Ethernet,"); // Taking a risk here
	if(ntohs(arp_hdr->protocol_type) == 0x800)
		fprintf(output_ptr,"IP,");
	else
		fprintf(output_ptr,"UNDEFINED,");
	fprintf(output_ptr,"%d,",arp_hdr->hardware_len);
	fprintf(output_ptr,"%d,",arp_hdr->protocol_len);

	if(ntohs(arp_hdr->opcode) == ARP_REQUEST)
		fprintf(output_ptr,"REQUEST,");
	else
		fprintf(output_ptr,"REPLY,");

	print_mac(arp_hdr->sender_mac);
	print_ip(arp_hdr->sender_ip);
	print_mac(arp_hdr->target_mac);
	print_ip(arp_hdr->target_ip);

}
void print_to_outputcsv(struct ether_header *eth_hdr,struct arp_header *arp_hdr, int error_type, int reason)
{
	print_eth_header(eth_hdr);
	print_arp_header(arp_hdr);

	if(error_type == FLAG_ERROR_PACKET)
	{
		fprintf(output_ptr,"ERROR,");
	}
	else if(error_type == FLAG_NOTICE_PACKET)
	{
		fprintf(output_ptr,"NOTICE,");
	}
	else
	{
		fprintf(output_ptr,"Unkown,");
	}

	switch(reason)
	{
	case ERROR_IP_SPOOFING:
		fprintf(output_ptr,"IP Spoofing,");
		break;
	case NOTICE_NOT_BROADCAST:
		fprintf(output_ptr,"Not a broadcast request,");
		break;
	case NOTICE_REPLY_BROADCAST:
		fprintf(output_ptr,"Reply is broadcast Gratuitous ARP,");
		break;
	case NOTICE_SPAM_REQUEST:
		fprintf(output_ptr,"Requested the same details more than %d times,",CONFIG_SPAM_DETECT_THRESHOLD);
		break;
	case ERROR_DESTINATION_MISMATCH:
		fprintf(output_ptr,"Destination MAC don't match in ARP and ETH header,");
		break;
	case ERROR_SOURCE_MISMATCH:
		fprintf(output_ptr,"Source MAC don't match in ARP and ETH header,");
		break;
	case ERROR_SOURCEIP_BROADCAST:
		fprintf(output_ptr,"Host is trying to bind IP broadcast address to its MAC,");
		break;
	default:
		break;
	}

	fprintf(output_ptr,"\n");

}


void init_spam_check_db()
{
	int i=0;
	for(i=0;i<CONFIG_SPAM_DB_SIZE;i++)
	{
		spam_check_db.spam_count[i]=0; // TODO: Use memset
	}
	spam_check_db.db_count = 0;
	printf("DB initialized\r\n");
}

void add_to_spam_check_db(struct ether_header *eth_hdr, struct arp_header *arp_hdr)
{
	int db_position = spam_check_db.db_count;
	if(db_position >= CONFIG_SPAM_DB_SIZE-1) // To prevent overflow
		return;// TODO: Do error handling

	spam_check_db.eth_hdr[db_position] = (struct ether_header *)malloc(sizeof(struct ether_header));
	memcpy(spam_check_db.eth_hdr[db_position],eth_hdr,sizeof(struct ether_header));

	spam_check_db.arp_hdr[db_position] = (struct arp_header *)malloc(sizeof(struct arp_header));
	memcpy(spam_check_db.arp_hdr[db_position],arp_hdr,sizeof(struct arp_header));

	spam_check_db.spam_count[db_position]++;

	spam_check_db.db_count++;
}

void check_if_spamming(struct ether_header *eth_hdr, struct arp_header *arp_hdr)
{
	int db_count = spam_check_db.db_count, i;

	struct arp_header *arp_hdr_db;

	for(i=0;i<db_count;i++)
	{
		arp_hdr_db = spam_check_db.arp_hdr[i];

		if(check_ip_same(arp_hdr_db->target_ip,arp_hdr->target_ip) == TRUE && check_mac_same(arp_hdr_db->sender_mac,arp_hdr->sender_mac) == TRUE)
		{
			printf("Recieved same request");
			spam_check_db.spam_count[i]++; // increment the spam count
			return;
		}
	}

	// Request not in db, add it
	add_to_spam_check_db(eth_hdr,arp_hdr);
}

void print_spam_check_db()
{
	int db_count = spam_check_db.db_count, i;

	struct ether_header *eth_hdr;
	struct arp_header *arp_hdr;

	for(i=0;i<db_count;i++)
	{
		eth_hdr = spam_check_db.eth_hdr[i];
		arp_hdr = spam_check_db.arp_hdr[i];

		//printf("DB%d,0x%x,%d,%d\r\n",ntohs(arp_hdr->hardware_type),ntohs(arp_hdr->protocol_type),arp_hdr->hardware_len,arp_hdr->protocol_len);
		//printf("Spam count %d\r\n",spam_check_db.spam_count[i]);

		if(spam_check_db.spam_count[i] >= CONFIG_SPAM_DETECT_THRESHOLD)
		{
			packet_count++;
			print_to_outputcsv(eth_hdr, arp_hdr,FLAG_NOTICE_PACKET,NOTICE_SPAM_REQUEST);
		}
	}
}



