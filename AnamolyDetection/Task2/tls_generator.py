# This script takes all the SSL/TLS data and it's output is redirected to a file by the bash script

import scapy
from scapy.layers.ssl_tls import *
import socket
import sys

temp = 1;
# print (sys.argv[1])
# Read data from the pcap file. 
raw_packets = rdpcap(sys.argv[1])

for packet in raw_packets:
	temp = temp+1
	print ("marker"),
	print temp
	# Check if it has TLS data 
	if(packet.haslayer("TLSRecord")):
		print packet["SSL/TLS"].show()