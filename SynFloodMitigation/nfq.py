from scapy.all import *
from netfilterqueue import NetfilterQueue

from scapy.config import conf
from scapy.supersocket import L3RawSocket

from threading import Thread
import threading
import time


syn_attack_table = {} # Table to store the ip's who have sent a SYN request
REQUEST_THRESHOLD = 5

lock = threading.Lock()


#This API sends a TCP reset packet to the server
def send_reset_server(ip,packet):

	print("Sending REset packet")
	conf.L3socket=L3RawSocket # Configuring this based on the issue found in : http://phaethon.github.io/scapy/api/troubleshooting.html#faq
	pkt = IP(packet.get_payload())
	tcp_sport=pkt[TCP].sport
	tcp_dport=pkt[TCP].dport

	ip = IP(src=ip,dst='127.0.0.1')
	syn = TCP(sport=tcp_sport, dport=tcp_dport, flags='R')
	packet = ip/syn
	send(packet,iface="lo")


	
# Add's the packet to the table if its a SYN request and greater than THRESHOLD
# return value: True -> The packet can be sent immediately 
# return value: False-> The packet is added to the queue, and will be sent later

def add_to_syn_table(ip,packet):
	global syn_attack_table
	retval = False
	if(ip in syn_attack_table):
		
		# Get the list contating the nubmer of requests for this ip and the list of pending requests
		requests = syn_attack_table[ip]
		# Increment the number of request for this IP
		requests[0] = requests[0] + 1

		if(requests[0] >= REQUEST_THRESHOLD):
			print("greater than threshold")
			send_reset_server(ip,packet)
			requests[1].append(packet)
			retval = False
		else:
			print("Less than threshold" + str(requests[0]))
			retval = True # Accept the packet immediately			
		# print(requests[0])
		# print(requests[1])
	else:
		# Create a new entry for the received request
		requests = [1,[]]
		retval = True

	lock.acquire()
	syn_attack_table[ip] = requests
	lock.release()
	return retval


# This thread sends the packets to the localhost server which are to be delayed
def rate_limitter_thread(active):
	global syn_attack_table
	print("Rate limitter thread started")
	while active.is_set():
		for ip in syn_attack_table:
			requests = syn_attack_table[ip]
			if not requests[1]: # IF no pending request continue
				print ("No requests to send")
				continue
			else: 
				pending_req_list = requests[1]
				print("sending rate limited packet")
				pending_req_list[0].accept()
				del pending_req_list[0]
				requests[1] = pending_req_list
				lock.acquire()
				syn_attack_table[ip] = requests
				lock.release()
		time.sleep(0.5)


# This API decrements the SYN request count for the given IP
def decrement_pending_request(ip):
	if(ip in syn_attack_table):
		lock.acquire()
		requests = syn_attack_table[ip]
		requests[0] = requests[0] - 1
		syn_attack_table[ip] = requests
		lock.release()

# Returns whether it is a SYN packet or a ACK packet
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

	# It is only sufficient to check if it is a SYN packet or an ACK packet

	if(curr_flag & SYN and (curr_flag & ACK == 0)):
		return 0
	elif(curr_flag & SYN and (curr_flag & ACK == 0)):
		return 1
	else: 
		return -1

# This is the callback function called whenver a new packet is received
def verify_packet(packet):
    pkt = IP(packet.get_payload()) #


    if not TCP in pkt: # Currently only checking for TCP packets, hence accept without verification if not a TCP
    	packet.accept()
    	return

    val = return_packet_type(pkt)

    if(val == 0): #SYN packet
    	print("SYN packet")
    	ip_src = pkt[IP].src
    	if(add_to_syn_table(ip_src,packet)):
    		print ("accepting immediately")
    		packet.accept()
    	else:
    		# packet will be sent later in a separte thread, nothing to do here
    		print ""
    elif(val == 1): # ACK packet
    	print("ACK packet")
    	ip_src = pkt[IP].src
    	packet.accept()
    	# Decrement the SYN request count of the ip from the syn_attack_table as we received an ACK
    	decrement_pending_request(ip_src)
    else: 
    	print("Not syn and ack packet")
    	packet.accept()


# For cleanly exiting the thread
active = threading.Event()
active.set()
# Create and start the thread for the rate limitter
thread = threading.Thread(target=rate_limitter_thread, args=(active,))
thread.start()

nfqueue = NetfilterQueue()
# Packets will be in queue 0, and the callback is verify_packet
nfqueue.bind(0, verify_packet) 
try:
    nfqueue.run()
except KeyboardInterrupt:
    active.clear()
    thread.join()
    nfqueue.unbind()