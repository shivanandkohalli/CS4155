/*
 * analysis.h
 *
 *  Created on: 23-Feb-2018
 *      Author: shiva
 */

#ifndef ANALYSIS_H_
#define ANALYSIS_H_

#include "main.h"
//-----------BEGIN Configurations------------------------------//
#define CONFIG_SPAM_DETECT_THRESHOLD_DEAUTH 5
#define CONFIG_SPAM_DETECT_THRESHOLD_ARP 100


#define CONFIG_SPAM_DB_SIZE 1000
#define CONFIG_DOT11_SPAM_DB_SIZE 1000

//-----------END Configurations------------------------------//

#define MAC_LENGTH 6
#define MAX_ARP_LENGTH 72

struct radiotap_header{
	uint8_t rev;
	uint8_t pad;
	uint16_t len;
};

struct deauth_header{
	//uint8_t type;
	uint16_t frame_control;
	uint16_t duration;
	uint8_t dest_address[6];
	uint8_t source_address[6];
	uint8_t bssid[6];
	uint16_t sequence_number;
	uint16_t reason_code;
};

struct dot11_header{
	uint16_t frame_control;
	uint16_t duration;
	uint8_t recv_address[6];
	uint8_t transmitter_address[6];
	uint8_t dest_address[6];
	uint16_t sequence_number;
	uint8_t source_address[6];
	uint8_t IV[4];
};

struct spam_check_database
{
	struct radiotap_header *radiotap_hdr[CONFIG_SPAM_DB_SIZE];
	struct deauth_header *deauth_hdr[CONFIG_SPAM_DB_SIZE];
	unsigned int spam_count[CONFIG_SPAM_DB_SIZE];
	unsigned int db_count;
};

struct dot11_spam_check_database
{
	struct radiotap_header *radiotap_hdr[CONFIG_SPAM_DB_SIZE];
	struct dot11_header *dot11_hdr[CONFIG_SPAM_DB_SIZE];
	unsigned int spam_count[CONFIG_SPAM_DB_SIZE];
	unsigned int db_count;
};

extern void analyse_pack(int packet_length, const u_char * packet);
extern void init_spam_check_db();
extern void print_spam_check_db();
extern void dot11_print_spam_check_db();
#endif /* ANALYSIS_H_ */
