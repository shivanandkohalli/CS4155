/*
 * events.c
 *
 *  Created on: 22-Feb-2018
 *      Author: shiva
 */

#include "events.h"
#include "packet_analyser.h"


void packet_recieved_event(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
	static int i = 0;
	//printf("i= : %d, %d",i++,pkthdr->len);
	analyse_pack(pkthdr->len, packet);
}

void initEvent(char *pcap_name, char *filter)
{
    pcap_t* descr;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;

	descr = pcap_open_offline(pcap_name, errbuf);
	if(pcap_compile(descr, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1)
	{
	   printf("Error calling pcap_compile: %s\n",pcap_geterr(descr));
	   exit(1);
	}

	if(pcap_setfilter(descr, &fp) == -1)
	{
	   printf("Error setting filter\n");
	   exit(1);
	}

	pcap_loop(descr, -1, packet_recieved_event, NULL);
}

void packet_recieved_raw(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
	analyse_packet_arp_replay(pkthdr->len, packet);
}


// Packets cannot be filtered as they are encrypted
void initEvent_arp(char *pcap_name)
{
    pcap_t* descr;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;

	descr = pcap_open_offline(pcap_name, errbuf);

	pcap_loop(descr, -1, packet_recieved_raw, NULL);
}


