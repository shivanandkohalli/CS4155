from scapy.all import *
from netfilterqueue import NetfilterQueue

from scapy.config import conf
from scapy.supersocket import L3RawSocket

from threading import Thread
import threading
import time
from scapy.layers import http

PACKET_SYN = 0
PACKET_SYN_ACK = 1
PACKET_ACK = 2
PACKET_UNKOWN = -1


# Returns whether it is a PACKET_SYN, PACKET_SYN_ACK, PACKET_ACK packet
def return_packet_type(pkt):
	FIN = 0x01
	SYN = 0x02
	RST = 0x04
	PSH = 0x08
	ACK = 0x10
	URG = 0x20
	ECE = 0x40
	CWR = 0x80

	curr_flag = pkt['TCP'].flags

	if((curr_flag & SYN) and (curr_flag & ACK)):
		return PACKET_SYN_ACK
	elif(curr_flag & SYN and (curr_flag & ACK == 0)):
		return PACKET_SYN
	elif((curr_flag & SYN == 0) and (curr_flag & ACK)):
		return PACKET_ACK
	else: 
		return PACKET_UNKOWN

def generate_sequence(pkt):
	return 15545

def send_syn_ack_client(pkt):
	sequence_to_send = generate_sequence(pkt)
	resp_syn_ack = IP(src=pkt['IP'].dst, dst=pkt['IP'].src)/TCP(sport=pkt['TCP'].dport, dport=pkt['TCP'].sport, flags="SA", seq=sequence_to_send, ack=pkt['TCP'].seq + 1)
	send(resp_syn_ack,iface="ens33")


def verify_client_ack(pkt):
	print ("ACK received")
	print (pkt['TCP'].ack)



# This is the callback function called whenver a new packet is received from a client
def client_stream(packet):
	print ("Client stream")
	pkt = IP(packet.get_payload())
	retval = return_packet_type(pkt)

	if(retval == PACKET_SYN):
		send_syn_ack_client(pkt)
	elif(retval == PACKET_ACK):
		verify_client_ack(pkt)
	else:
		print ("Unkown packet")
	# packet.accept()

# This is the callback function called whenver a new packet is being sent from server
def server_stream(packet):
	print ("server steam")
	# packet.accept()


# Start receving packets from the nfqueue
client = NetfilterQueue()
server = NetfilterQueue()
# Packets will be in queue 0, and the callback is client_stream
client.bind(0, client_stream) 
server.bind(1, server_stream) 

try:
    client.run()
    server.run()
except KeyboardInterrupt:
    client.unbind()
    server.unbind()
