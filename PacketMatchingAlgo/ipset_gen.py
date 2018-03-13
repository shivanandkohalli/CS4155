import subprocess
import socket
import struct
random_ip = 168430090
count = 2000000
iphash_size_limit = 50000

for j in range(2,(count/iphash_size_limit)):
	# Create a new set 
	set_name = "firewall_set" + str(j)
	subprocess.call(["sudo","ipset","-N",set_name,"iphash"])
	print ("Setting"),
	print j
	for i in range(0,iphash_size_limit):
		ip_gen = socket.inet_ntoa(struct.pack("!I", i + random_ip +iphash_size_limit*j))
		subprocess.call(["sudo","ipset","-A",set_name,ip_gen])


# sudo iptables -A INPUT -m set --match-set firewall_set src -j DROP
