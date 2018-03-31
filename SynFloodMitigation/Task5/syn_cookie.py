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

STATE_SERVER_CONN = 1 # Client has completed its syn cookie verification, connection with server pending
STATE_WHITELIST = 2 # Client IP is whitelisted, can communicate with server now
STATE_NOT_WHITE_LIST = 3 # IP is not yet whitelisted

ip_whitelist_table = {}

# REturn the state of the IP from the whitelist table
def get_ip_state(ip):
	global ip_whitelist_table
	if ip in ip_whitelist_table:
		return ip_whitelist_table[ip]
	else:
		return STATE_NOT_WHITE_LIST

# Add the state of the IP address to the table 
def add_to_whitelist_ip(ip, state):
	global ip_whitelist_table
	ip_whitelist_table[ip] = state

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


def send_syn_server(pkt):
	conf.L3socket = L3RawSocket
	resp_syn = IP(src=pkt['IP'].src, dst=pkt['IP'].dst)/TCP(sport=pkt['TCP'].sport, dport=pkt['TCP'].dport, flags="S", seq=pkt['TCP'].seq-2)
	send(resp_syn,iface="lo")


def verify_client_ack(pkt):
	print (pkt['TCP'].ack)
	add_to_whitelist_ip(pkt['IP'].src,STATE_SERVER_CONN)
	send_syn_server(pkt)

def send_ack_server(pkt):
	conf.L3socket = L3RawSocket
	resp_syn = IP(src=pkt['IP'].dst, dst=pkt['IP'].src)/TCP(sport=pkt['TCP'].dport, dport=pkt['TCP'].sport, flags="A", seq=pkt['TCP'].ack,ack=pkt['TCP'].seq + 1)
	send(resp_syn,iface="lo")	

# This is the callback function called whenver a new packet is received from a client
def client_stream(packet):
	print ("Client stream")
	pkt = IP(packet.get_payload())
	retval = return_packet_type(pkt)

	if(get_ip_state(pkt['IP'].src)==STATE_WHITELIST):
		print("whitelisted")
		packet.accept()
	elif(retval == PACKET_SYN and (get_ip_state(pkt['IP'].src)==STATE_NOT_WHITE_LIST)): # Client trying for the first time
		print("Client SYN packet")
		send_syn_ack_client(pkt)
	elif(retval == PACKET_SYN and (get_ip_state(pkt['IP'].src)==STATE_SERVER_CONN)): # This is the packet sent by IDS itself, allow it to communicate to server
		print("Client, LOCAL SYN packet")
		packet.accept()
	elif(retval == PACKET_ACK and (get_ip_state(pkt['IP'].src)==STATE_NOT_WHITE_LIST)): # Client trying for the first time
		print("ACK received from client")
		verify_client_ack(pkt)
	elif(retval == PACKET_ACK and (get_ip_state(pkt['IP'].src)==STATE_SERVER_CONN)): # This is the packet sent by IDS itself, allow it to communicate to server
		print("ACK from LOCKAL IDS")
		packet.accept()
	else:
		print ("Unkown packet")
		packet.drop()
	# packet.accept()


# This is the callback function called whenver a new packet is being sent from server
def server_stream(packet):
	print ("server stream")
	pkt = IP(packet.get_payload())
	retval = return_packet_type(pkt)

	if(get_ip_state(pkt['IP'].dst) ==STATE_WHITELIST):
		print("Sending to whitelisted ip from server")
		packet.accept()
	elif(retval == PACKET_SYN_ACK):
		print("Recevied SYN ACK from server")
		send_ack_server(pkt)	
		add_to_whitelist_ip(pkt['IP'].dst,STATE_WHITELIST)
	else:
		print ("Received unkown packet from server")	
		packet.accept() # Accept the packet sent from the server if not SYN ACK
	# packet.accept()

# This thread is to start reading all the data from server
def start_server_com():
	server = NetfilterQueue()
	server.bind(1, server_stream) 
	try:
		server.run()
	except KeyboardInterrupt:
		server.unbind()

# add_to_whitelist_ip('192.168.0.102',STATE_WHITELIST)
# For cleanly exiting the thread
active = threading.Event()
active.set()
# Create and start the thread for the rate limitter
thread = threading.Thread(target=start_server_com)
thread.start()

# Start receving packets from the nfqueue
client = NetfilterQueue()

# Packets will be in queue 0, and the callback is client_stream
client.bind(0, client_stream) 


try:
    client.run()
    server.run()
except KeyboardInterrupt:
    client.unbind()
    server.unbind()
