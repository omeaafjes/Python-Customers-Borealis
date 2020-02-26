import json
import sys
import re

infile1=sys.argv[1]
infile2=sys.argv[2]

with open(infile1,'r') as f:
	fw=json.load(f)

g=open(infile2,'r')
file_in=g.read()
inlist=file_in.splitlines()
inlist=list(inlist)


fwpol=fw["configuration"]["security"]["policies"]["policy"]
le=len(fwpol)

def printl(inp):
	if isinstance(inp,list):
		l=len(inp)
		for x in inp[0:-1]:
			print x+";",
		print inp[l-1],
	else:
		print inp,

def printPol(x,y,z):
	print x+",",
	print z+",",
	print y["name"]+",",
        printl(y["match"]["source-address"])
        print ",",
        printl(y["match"]["destination-address"])
        print ",",
        printl(y["match"]["application"])
        print ",",
        printl(y["then"].keys())
        print

def common(x,y):
        a=set(x)
        b=set(y)
        if (a & b):
                return True
        else:
                return False




for x in fwpol:
		xpol=x["policy"]
		dzone=x["to-zone-name"]
		szone=x["from-zone-name"]
		match_to=re.search(r'0*(\d+)',dzone)
		if match_to != None:
			mt=match_to.group(1)
		else:
			mt=''
		match_from=re.search(r'0*(\d+)',szone)
		if match_from != None:
			mf=match_from.group(1)
		else:
			mf=''
		if mf in inlist or mt in inlist:
			if isinstance(xpol,list):
				for p in xpol:
					printPol(szone,p,dzone)
	
			else:
				printPol(szone,xpol,dzone)



	
	
