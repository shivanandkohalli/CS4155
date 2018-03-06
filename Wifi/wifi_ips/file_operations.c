/*
 * file_operations.c
 *
 *  Created on: 23-Feb-2018
 *      Author: shiva
 */

#include "file_operations.h"
#include <string.h>


void init_output_csv(char *file1, char *file2)
{
	deauth_ptr = fopen(file1,"w");
	fprintf(deauth_ptr,"frame_control,duration,receiver_addrees,dest_address,transmitter_address,source_address,bssid,sequence_number,reason_code,COUNT(No of same packet)\n");

	arp_replay_ptr = fopen(file2,"w");
	fprintf(arp_replay_ptr,"frame_control,duration,recv_address,transmitter_address,dest_address,sequence_number,source_address,IV,COUNT(No of same packet)\n");

	return;
}
