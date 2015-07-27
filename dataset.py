import sys
import random
import itertools

# FOR MAIN PART, GO TO THE BOTTOM 

# OUTPUT: permutation of bits
def bit_combinations(n):
	lst = map(list, itertools.product([0, 1], repeat=n))
	return lst

# OUTPUT: 3232236598
def int_from_ip( str ):
	return int(netaddr.IPAddress(str))

# OUTPUT: 192.168.4.54
def ip_string_from_int( int ):
	return str(netaddr.IPAddress(int))

# OUTPUT: 255.255.255.0
def return_mask(str, len):
	return 1

# OUTPUT: 254320432
def int_from_bit_string (str):
	return int(str, 2)

# OUTPUT:
def generate_rule (str):
	#print str.count('x')
	print len(bit_combinations(str.count('x')))

# OUTPUT: 100100010101010**10*...
def generate_bit_field( len, p):
	s=""

	for i in range(0, len):
		rnd = random.random()
		if(rnd < p):
			s+= "x"
		else:
			if( rnd < (p+1)/2):
				s+= "1"
			else:
				s+= "0"
	return s

def print_line_file(file, list):
	s=""
	for str in list:
		s+=str
		s+=" "	

	file.write(s)
	file.write("\n")

############ MAIN ###############

file = open("generated.txt", "w")
file2 = open("prefix_generated.txt", "w")
random.seed(1)

p = 0.3
n = 300
f = ["IPS", "IPD", "PRTS", "PRTD", "PROTO", "FROM", "ICMP"]	#Standard version
type = 0
length = {"IPS":32, "IPD":32, "PRTS":16, "PRTD":16, "PROTO":5, "FROM":3, "ICMP":3}


if (len(sys.argv)<2):	
	print ("Usage:\n python dataset.py [-p probability] [-n NUM ELEMENTS] [-f num fields] [-t TYPE] ") 
	print ("TYPE: general, prefix, exacts, ... ")
	print ("DEFAULT: p  = 0.6, n = 1000, f = 7, t = general")
	print ("Fields:" ,f)
	print ("Field length:" , length)
	exit()

for i in range(0, len(sys.argv)/2):
	if(sys.argv[2*i+1] == "-p"):
		p = sys.argv[2*i+2]
	if(sys.argv[2*i+1] == "-n"):
		n = sys.argv[2*i+2]
	if(sys.argv[2*i+1] == "-t"):
		if(sys.argv[2*i+2]=="prefix"):
			type = 1
	if(sys.argv[2*i+1] == "-f"):
		h = int(sys.argv[2*i+2])
		f = []
		length = {}
		for n in (range (0, h) ):
			s="FIELD"+str(n)
			f.append(s)
			length[s] = 32

print "Starting with ", "p=",p, "NUM ELEM=", n, "NUM FIELD=", f, type


## GENERATE FIELD FOR EVERY RULE
data = []
str = ""

for i in range(0, n):	# For each rule
	for args in f:		# For each field
		a = generate_bit_field (length[args], p)
		data.append( a )
		str+=a
		str+=" "

	new_rules = generate_rule(str)	# Generate VeriFlow rules

	print_line_file(file, data)	# Print string like this in the non parsed data file
	data = []
	str=""


#print data
#b = generate_bit_field(32, p)
#a = int_from_bit_string( b )
#print a, b
