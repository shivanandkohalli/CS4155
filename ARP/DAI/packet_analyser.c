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


void analyse_packet(int packet_length, const u_char* packet)
{

	struct ether_header *eth_hdr;
	struct arp_header *arp_hdr;

	int retval;

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
//	printf("Hardware type %d\r\n",ntohs(arp_hdr->hardware_type));
//	printf("Protocol type %x\r\n",ntohs(arp_hdr->protocol_type));
//	printf("hardware_len %d\r\n",(arp_hdr->hardware_len));
//	printf("protocol_len %d\r\n",(arp_hdr->protocol_len));
//	printf("opcode %d\r\n",ntohs(arp_hdr->opcode));

//    if(find_in_acl(arp_hdr->sender_mac, arp_hdr->sender_ip))
//    {
//    	printf("Present in list");
//    }
//    else
//    {
//    	printf("Not present in list");
//    }

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
    	  printf("Error check_mac_consistency:Shouldnt reach here");
    	  break;
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
static int check_ip_same(unsigned char *ip1, unsigned char *ip2)
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



//void construct_macip_str(sender_mac, sender_ip, mac_ip);
//{
//
//}
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

	fprintf(output_ptr,"Packet_%d,",packet_count++);
	print_mac(eth_hdr->ether_dhost);
	print_mac(eth_hdr->ether_shost);
	fprintf(output_ptr,"ARP,");

}

static void print_arp_header(struct arp_header *arp_hdr)
{
	//	printf("Hardware type %d\r\n",ntohs(arp_hdr->hardware_type));
	//	printf("Protocol type %x\r\n",ntohs(arp_hdr->protocol_type));
	//	printf("hardware_len %d\r\n",(arp_hdr->hardware_len));
	//	printf("protocol_len %d\r\n",(arp_hdr->protocol_len));
	//	printf("opcode %d\r\n",ntohs(arp_hdr->opcode));
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
    	fprintf(output_ptr,"Reply is broadcast, Gratuitous ARP,");
  	  break;
    case ERROR_DESTINATION_MISMATCH:
    	fprintf(output_ptr,"Destination MAC don't match,");
  	  break;
    case ERROR_SOURCE_MISMATCH:
    	fprintf(output_ptr,"Source MAC don't match,");
  	  break;
	default:
		break;
	}

	fprintf(output_ptr,"\n");

}



