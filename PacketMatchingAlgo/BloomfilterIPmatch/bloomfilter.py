from bitarray import bitarray
import xxhash
import socket
import struct
import datetime

class BloomFilter:
	def __init__(self,size,k):
		self.size = size
		self.bit_array = bitarray(size)
		self.bit_array.setall(False)
		self.k = k

	def getbit_array(self,pos):
		return self.bit_array[pos]

	def setbit_array(self,pos):
		self.bit_array[pos] = True


	def getHash_pos(self,val):
		hash_pos_list = []
		for i in range(0,self.k):
			hash_pos_list.append(int(xxhash.xxh32(val, seed=i).hexdigest(),16) % self.size)
		return hash_pos_list
		# return int(xxhash.xxh32(val, seed=1).hexdigest(),16) % self.size

	def add_to_filter(self,val):
		for i in range(0,self.k):
			pos = int(xxhash.xxh32(val, seed=i).hexdigest(),16) % self.size
			self.setbit_array(pos)


	def is_present(self,val):
		hash_pos_list = self.getHash_pos(val)
		for pos in hash_pos_list:
			if(self.getbit_array(pos) == False):
				return False
		return True



count = 2000000
resolution = 100000

table = BloomFilter(17500000000,30)
# table = BloomFilter(175000,30)
random_ip = 168430090

for i in range(0,count):
	table.add_to_filter(socket.inet_ntoa(struct.pack("!I", random_ip+i)))
	if((i+1)%resolution == 0):
		print (i+1),"\t",
		for count in range(0,10):
			x = datetime.datetime.now()	#start timer
			table.is_present("192.10.10.18") #some random ip
			y = datetime.datetime.now() #stop timer
			z = y-x
			print (z.microseconds),"\t",
		print ("\n")
