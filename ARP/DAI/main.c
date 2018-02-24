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

FILE *output_ptr;


int main(int argc,char **argv)
{
	FILE *config_file;

	config_file = fopen(argv[1],"r");
	if(config_file == NULL)
	{
		printf("ERROR: Configuration file not found, exiting");
		//return -1;
	}
	init_packet_analyser(config_file);

	output_ptr = init_output_csv(argv[3]);

	initEvent(argv[2], "arp");

	print_acl_list();
	return 1;
}

