/*
 * analysis.c
 *
 *  Created on: 23-Feb-2018
 *      Author: shiva
 */

#include "packet_analyser.h"
#include "file_operations.h"

struct spam_check_database spam_check_db;

struct dot11_spam_check_database dot11_spam_check_db;

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

void analyse_pack(int packet_length, const u_char * packet)
{

	struct radiotap_header *radiotap_hdr = (struct radiotap_header *) packet;

	struct deauth_header *deauth_hdr = (struct deauth_header*) (packet + radiotap_hdr->len);

	check_dos_attack(radiotap_hdr,deauth_hdr);

	return;
}


void analyse_packet_arp_replay(int packet_length, const u_char * packet)
{

	struct radiotap_header *radiotap_hdr = (struct radiotap_header *) packet;

	struct dot11_header *dot11_hdr = (struct dot11_header*) (packet + radiotap_hdr->len);

	check_arp_attack(radiotap_hdr,dot11_hdr,packet_length);

	return;
}

// Check if the data size is less than the MAX_ARP_LENGTH
void check_arp_attack(struct radiotap_header *radiotap_hdr, struct dot11_header *dot11_hdr, int packet_length)
{
	int db_count = dot11_spam_check_db.db_count, i;
	int data_length;
	data_length = packet_length -(radiotap_hdr->len+sizeof(struct dot11_header));

	struct dot11_header *dot11_hdr_db;

	if(data_length > 0 && data_length <= MAX_ARP_LENGTH)
	{
		for(i=0;i<db_count;i++)
		{
			dot11_hdr_db = dot11_spam_check_db.dot11_hdr[i];
			if(check_mac_same(dot11_hdr->source_address,dot11_hdr_db->source_address)==TRUE && check_mac_same(dot11_hdr->dest_address,dot11_hdr_db->dest_address)==TRUE)
			{
				//printf("Recieved same request");
				dot11_spam_check_db.spam_count[i]++; // increment the spam count
				return;
			}
		}
	}
	else
	{
		return;
	}
	dot11_add_to_spam_check_db(radiotap_hdr,dot11_hdr);
	return;
}


void check_dos_attack(struct radiotap_header *radiotap_hdr, struct deauth_header *deauth_hdr)
{
	int db_count = spam_check_db.db_count, i;

	struct deauth_header *deauth_hdr_db;

	for(i=0;i<db_count;i++)
	{
		deauth_hdr_db = spam_check_db.deauth_hdr[i];

		if(check_mac_same(deauth_hdr_db->source_address,deauth_hdr->source_address) == TRUE && check_mac_same(deauth_hdr_db->dest_address,deauth_hdr->dest_address) == TRUE)
		{
			//printf("Recieved same request");
			spam_check_db.spam_count[i]++; // increment the spam count
			return;
		}
	}

	// Request not in db, add it
	add_to_spam_check_db(radiotap_hdr,deauth_hdr);
}


void init_spam_check_db()
{
	int i=0;
	for(i=0;i<CONFIG_SPAM_DB_SIZE;i++)
	{
		spam_check_db.spam_count[i]=0; // TODO: Use memset
	}
	spam_check_db.db_count = 0;

	for(i=0;i<CONFIG_DOT11_SPAM_DB_SIZE;i++)
	{
		spam_check_db.spam_count[i]=0; // TODO: Use memset
	}
	dot11_spam_check_db.db_count = 0;

	printf("DB initialized\r\n");
}

void dot11_add_to_spam_check_db(struct radiotap_header *radiotap_hdr, struct dot11_header *dot11_hdr)
{
	int db_position = dot11_spam_check_db.db_count;
	if(db_position >= CONFIG_DOT11_SPAM_DB_SIZE-1) // To prevent overflow
		return;// TODO: Do error handling

	dot11_spam_check_db.radiotap_hdr[db_position] = (struct radiotap_header *)malloc(sizeof(struct radiotap_header));
	memcpy(dot11_spam_check_db.radiotap_hdr[db_position],radiotap_hdr,sizeof(struct radiotap_header));

	dot11_spam_check_db.dot11_hdr[db_position] = (struct dot11_header *)malloc(sizeof(struct dot11_header));
	memcpy(dot11_spam_check_db.dot11_hdr[db_position],dot11_hdr,sizeof(struct dot11_header));

	dot11_spam_check_db.spam_count[db_position]++;

	dot11_spam_check_db.db_count++;
}


void add_to_spam_check_db(struct radiotap_header *radiotap_hdr, struct deauth_header *deauth_hdr)
{
	int db_position = spam_check_db.db_count;
	if(db_position >= CONFIG_SPAM_DB_SIZE-1) // To prevent overflow
		return;// TODO: Do error handling

	spam_check_db.radiotap_hdr[db_position] = (struct radiotap_header *)malloc(sizeof(struct radiotap_header));
	memcpy(spam_check_db.radiotap_hdr[db_position],radiotap_hdr,sizeof(struct radiotap_header));

	spam_check_db.deauth_hdr[db_position] = (struct deauth_header *)malloc(sizeof(struct deauth_header));
	memcpy(spam_check_db.deauth_hdr[db_position],deauth_hdr,sizeof(struct deauth_header));

	spam_check_db.spam_count[db_position]++;

	spam_check_db.db_count++;
}

void dot11_print_spam_check_db()
{
	int db_count = dot11_spam_check_db.db_count, i;

	struct radiotap_header *radiotap_hdr;
	struct dot11_header *dot11_hdr;

	for(i=0;i<db_count;i++)
	{
		radiotap_hdr = dot11_spam_check_db.radiotap_hdr[i];
		dot11_hdr = dot11_spam_check_db.dot11_hdr[i];


		if(dot11_spam_check_db.spam_count[i] >= CONFIG_SPAM_DETECT_THRESHOLD_ARP)
		{
			//packet_count++;
			print_to_outputcsv_dot11(dot11_hdr);
			printf("Spam count = %d\r\n",dot11_spam_check_db.spam_count[i]);
		}
	}
}
static void print_mac(FILE *output_ptr, unsigned char *mac)
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


void print_to_outputcsv_dot11(struct dot11_header *dot11_hdr)
{
	fprintf(arp_replay_ptr, "%x,%d,",ntohs(dot11_hdr->frame_control),ntohs(dot11_hdr->duration));
	print_mac(arp_replay_ptr,dot11_hdr->recv_address);
	print_mac(arp_replay_ptr,dot11_hdr->transmitter_address);
	print_mac(arp_replay_ptr,dot11_hdr->dest_address);
	fprintf(arp_replay_ptr,"%d,",ntohs(dot11_hdr->sequence_number));
	print_mac(arp_replay_ptr,dot11_hdr->source_address);
	fprintf(arp_replay_ptr,"%x,",(dot11_hdr->IV[0]<<16 | dot11_hdr->IV[1]<<8 | dot11_hdr->IV[2]));
	fprintf(arp_replay_ptr,"\n");
}

void print_to_outputcsv_deauth(struct deauth_header *deauth_hdr, int count)
{
	fprintf(deauth_ptr, "%x,%d,",ntohs(deauth_hdr->frame_control),ntohs(deauth_hdr->duration));
	print_mac(deauth_ptr,deauth_hdr->dest_address);
	print_mac(deauth_ptr,deauth_hdr->dest_address);
	print_mac(deauth_ptr,deauth_hdr->source_address);
	print_mac(deauth_ptr,deauth_hdr->source_address);
	print_mac(deauth_ptr,deauth_hdr->bssid);
	fprintf(deauth_ptr,"%d,",ntohs(deauth_hdr->sequence_number));
	fprintf(deauth_ptr,"%x,",(deauth_hdr->reason_code));
	fprintf(deauth_ptr,"%d,",count);
	fprintf(deauth_ptr,"\n");
}

//void print_frameheader(uint16_t frame_header)
//{
//	printf("Frame header\n%d\n", (frame_header & 0xC000)>>14);
//	printf("Frame header\n%d\n", (frame_header & 0x3000)>>12);
//	printf("Frame header\n%d\n", (frame_header & 0x0F00)>>12);
//
//}



void print_spam_check_db()
{
	int db_count = spam_check_db.db_count, i;

	struct radiotap_header *radiotap_hdr;
	struct deauth_header *deauth_hdr;

	for(i=0;i<db_count;i++)
	{
		radiotap_hdr = spam_check_db.radiotap_hdr[i];
		deauth_hdr = spam_check_db.deauth_hdr[i];

		//printf("DB%d,0x%x,%d,%d\r\n",ntohs(arp_hdr->hardware_type),ntohs(arp_hdr->protocol_type),arp_hdr->hardware_len,arp_hdr->protocol_len);
		//printf("Spam count %d\r\n",spam_check_db.spam_count[i]);

		if(spam_check_db.spam_count[i] >= CONFIG_SPAM_DETECT_THRESHOLD_DEAUTH)
		{
			//packet_count++;
			print_to_outputcsv_deauth(deauth_hdr,spam_check_db.spam_count[i]);
			printf("Spam count = %d",spam_check_db.spam_count[i]);
		}
	}
}


