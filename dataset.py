import math
import sys
import random
import itertools
import mask
import socket, struct

# SOME DEF
mask = {}

mask[0]= '255.255.255.255'
mask[1]= '255.255.255.254'
mask[2]= '255.255.255.252'
mask[3]= '255.255.255.248'
mask[4]= '255.255.255.240'
mask[5]= '255.255.255.224'
mask[6]= '255.255.255.192'
mask[7]= '255.255.255.128'
mask[8]= '255.255.255.0'
mask[9]= '255.255.254.0'
mask[10]= '255.255.252.0'
mask[11]= '255.255.248.0'
mask[12]= '255.255.240.0'
mask[13]= '255.255.224.0'
mask[14]= '255.255.192.0'
mask[15]= '255.255.128.0'
mask[16]= '255.255.0.0'
mask[17]= '255.254.0.0'
mask[18]= '255.252.0.0'
mask[19]= '255.248.0.0'
mask[20]= '255.240.0.0'
mask[21]= '255.224.0.0'
mask[22]= '255.192.0.0'
mask[23]= '255.128.0.0'
mask[24]= '255.0.0.0'
mask[25]= '254.0.0.0'
mask[26]= '252.0.0.0'
mask[27]= '248.0.0.0'
mask[28]= '240.0.0.0'
mask[29]= '224.0.0.0'
mask[30]= '192.0.0.0'
mask[31]= '128.0.0.0'
mask[32]= '0.0.0.0'


# FOR MAIN PART, GO TO THE BOTTOM 

# OUTPUT: permutation of bits
def bit_combinations(n):
	lst = map(list, itertools.product([0, 1], repeat=n))
	return lst

# OUTPUT: 3232236598
def int_from_ip( string ):
	return int(netaddr.IPAddress(string))

# OUTPUT: 192.168.4.54
def ip_string_from_int( int ):
	return socket.inet_ntoa(struct.pack("!I", int))
	#return str(netaddr.IPAddress(int))

# OUTPUT: 255.255.255.0
def return_mask(string, len):
	return 1

# OUTPUT: 254320432
def int_from_bit_string (string):
	return int(string, 2)

# OUTPUT:
def generate_rule (string, type):
	lists = []
	#print str.count('x')
	if(type==0):
		comb = bit_combinations(string.count('x'))

		for elem in comb:
			i=0
			j=0
			local = list(string)
			for character in local:
				if(character == 'x'):
					if (elem[i]==0):
						local[j] = '0'
					else:
						local[j] = '1'
					i+=1
				j+=1

			local= ''.join(local)

			#print local
			new_string=""
			for elem in local.split():
				#new_string+=elem
				if (len(elem)<30):
					a=int_from_bit_string(elem)
					#print str(a)
					new_string+=str(a)
					new_string+=" "
					new_string+=str(int(math.pow(2, len(elem)-1)))
					#print str(int(math.pow(2, len(elem))-1))

				else:
					new_string+= ip_string_from_int(int_from_bit_string(elem))
					new_string+=" 255.255.255.255 "

			file2= open("prefix_generated.txt", "a")
			file2.write(new_string)
			file2.write("\n")
			file2.close()
			#print new_string

			lists.append(new_string)
	else:
		s=""		
		for string_s in string.split():
			#print len(string.split())
			#print string_s.count('x')
			m = string_s.count('x')
			local = mask[m]
			
			#s+=string.replace("x", "0")
			if(len(string_s)<30):
				s+= str(int_from_bit_string(string_s.replace("x", "0")))
				s+=" "
				s+=str(  int(math.pow(2, len(string_s))) - int(math.pow(2, m))  )
			else:
				s+= ip_string_from_int(int_from_bit_string(string_s.replace("x", "0")))
				s+=" "
				s+=local	
			s+=" "
                        
		file2= open("prefix_generated.txt", "a")
                file2.write(s)
                file2.write("\n")
                file2.close()

		lists.append(s)
		#print ("lists size")
		#print len(lists)

	return lists

# OUTPUT: 100100010101010**10*...
def generate_bit_field( len, p, type):
	s=""

	s1=""
	s2=""

	for i in range(0, len):
		rnd = random.random()
		#print rnd
		if(rnd < p):
			s+= "x"
			s2+="x"
		else:
			if( rnd < (p+1)/2):
				s+= "1"
				s1+="1"
			else:
				s+= "0"
				s1+="0"

	if(type==0):
		return s
	else:
		s1+=s2
		#print s1
		return s1



def print_line_file(file, list):
	s=""
	for string in list:
		s+=string
		s+=" "	

	file.write(s)
	file.write("\n")

############ MAIN ###############

file = open("generated.txt", "w")
file2 = open("prefix_generated.txt", "w")
file2.close()
random.seed(1)

p = 0.05
n = 300
f = ["IPS", "IPD", "PRTS", "PRTD", "PROTO", "FROM", "ICMP"]	#Standard version
type = 0
length = {"IPS":32, "IPD":32, "PRTS":16, "PRTD":16, "PROTO":5, "FROM":3, "ICMP":3}


if (len(sys.argv)<2):	
	print ("Usage:\n python dataset.py [-p probability] [-n NUM ELEMENTS] [-f num fields] [-t TYPE] ") 
	print ("TYPE: general, prefix, exacts, ... ")
	print ("DEFAULT: p  = 0.6, n = 300, f = 7, t = general")
	print ("Fields:" ,f)
	print ("Field length:" , length)
	exit()

for i in range(0, len(sys.argv)):
	if(sys.argv[i] == "-p"):
		p = sys.argv[i+1]
	if(sys.argv[i] == "-n"):
		n = int(sys.argv[i+1])
		print "Detected n", n
		print n
	if(sys.argv[i] == "-t"):
		if(sys.argv[i+1]=="prefix"):
			type = 1
	if(sys.argv[i] == "-f"):
		h = int(sys.argv[i+1])
		f = []
		length = {}
		for g in (range (0, h) ):
			s="FIELD"+str(g)
			f.append(s)
			length[s] = 32

print f
print "Starting with ", "p=",p, "NUM ELEM=", n, "NUM FIELD=", f, type


## GENERATE FIELD FOR EVERY RULE
data = []
string = ""

for i in range(0, n):	# For each rule
	for args in f:		# For each field
		a = generate_bit_field (length[args], p, type)
		data.append( a )
		string+=a
		string+=" "

	#print string
	new_rules = generate_rule(string, type)	# Generate VeriFlow rules
	print_line_file(file, data)	# Print string like this in the non parsed data file

	#print len(new_rules)

	data = []
	string=""
	new_rules=[]


#print data
#b = generate_bit_field(32, p)
#a = int_from_bit_string( b )
#print a, b
