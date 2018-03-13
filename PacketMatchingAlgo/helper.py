with open("ping.txt","r") as fh:
	content = fh.readlines()

for line in content:
	words = line.split()
	time = words[6].split("=")
	print (time[1] + "\t"),