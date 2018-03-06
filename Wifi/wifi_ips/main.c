/*
 * main.c
 *
 *  Created on: 22-Feb-2018
 *      Author: shiva
 */

#include "main.h"
#include "events.h"
#include "file_operations.h"
#include "packet_analyser.h"

FILE *deauth_ptr;
FILE *arp_replay_ptr;


int main(int argc,char **argv)
{


	init_output_csv("task1.csv","task2.csv");

	init_spam_check_db();
	initEvent(argv[1], "type mgt subtype deauth or subtype disassoc");
	print_spam_check_db();
	fclose(deauth_ptr);

	initEvent_arp(argv[2],"temp");
	dot11_print_spam_check_db();
	fclose(arp_replay_ptr);
	return 1;
}

