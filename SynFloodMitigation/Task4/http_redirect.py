from scapy.all import *
from netfilterqueue import NetfilterQueue

from scapy.config import conf
from scapy.supersocket import L3RawSocket

from threading import Thread
import threading
import time
from scapy.layers import http


http_request_table = {} # Table to store the ip's who have sent the http request



# Checks if the IP has an entry in the table with a value of 1->whitelisted or 0->not whitelisted,
# if whitelisted: return True so that the requests from the IP can be accepted
# if not whitelisted: return False, so that it needs to do the proof of work by going to the redirected page
# store the path the IP was querying(only done 1st time) 
def add_to_http_table(ip,path):
	global http_request_table
	if(ip in http_request_table):
		req_list = http_request_table[ip]
		val = req_list[0]
		if(val == 1):
			return True
		elif(val == 0):
			return False
	else:
		http_request_table[ip] = [0,path]
		return False

# Whitelist the given ip, and send the actual request to the resource it had done previoulsy
def whitelist_ip(ip):
	global http_request_table
	if(ip in http_request_table):
		req_list = http_request_table[ip]
		req_list[0] = 1
		http_request_table[ip] = req_list
		return req_list[1]
	else:
		return None

# Create and send the HTTP response, takes care of the sequence number and acknowledgement number in the response
def send_redirect_resp(resource,pkt):
	conf.L3socket = L3RawSocket
	resp = "HTTP/1.1 302 Found\r\nLocation: " + resource + "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
	resp_http = IP(src=pkt['IP'].dst, dst=pkt['IP'].src)/TCP(sport=pkt['TCP'].dport, dport=pkt['TCP'].sport, flags="PA", seq=pkt['TCP'].ack , ack=pkt['TCP'].seq + (pkt['IP'].len - 52))
	# resp = HTTP('Http-Version'='HTTP/1.1',)
	send(resp_http/Raw(load=resp),iface="ens33")

# This is the callback function called whenver a new packet is received
def verify_packet(packet):
    print ("received packets")
    pkt = IP(packet.get_payload()) # for a scapy compatible data structure
    if(pkt.haslayer("HTTP")):
    	# Check if a client is requesting the redirected request ("/hello"  here)
    	if(pkt["HTTP"].Method == "GET" and (pkt["HTTP"].Path) == "/hello"):
    		actual_request = whitelist_ip(pkt['IP'].src)
    		print("recived redirected request")
    		send_redirect_resp(actual_request,pkt)
    	# Check if a client is requesting anything other than redirected resource
    	elif(pkt["HTTP"].Method == "GET"):
    		print("received index request")
    		# print (pkt.show())
    		retval = add_to_http_table(pkt['IP'].src, pkt["HTTP"].Path)
    		if(retval == True):
    			    packet.accept()
    		else:
    			send_redirect_resp("/hello",pkt)
    else:
    	packet.accept()


    

# Start receving packets from the nfqueue
nfqueue = NetfilterQueue()
# Packets will be in queue 0, and the callback is verify_packet
nfqueue.bind(0, verify_packet) 
try:
    nfqueue.run()
except KeyboardInterrupt:
    nfqueue.unbind()