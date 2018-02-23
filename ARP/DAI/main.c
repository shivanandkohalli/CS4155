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


int main(int argc,char **argv)
{
	FILE *fp;

	fp = fopen(argv[1],"r");
	if(fp == NULL)
	{
		printf("ERROR: Configuration file not found, exiting");
		return -1;
	}
	init_packet_analyser(fp);
	initEvent(argv[2], "arp");
	return 1;
}

