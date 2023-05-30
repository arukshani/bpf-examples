#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
 
int main(int argc,char **argv)
{
    int sockfd,n;
    char sendline[100] = "Packet";
    char recvline[100];
    struct sockaddr_in servaddr;
 
    sockfd=socket(AF_INET,SOCK_STREAM,0);
    // sockfd=socket(AF_INET,SOCK_DGRAM,0);
    bzero(&servaddr,sizeof servaddr);
 
    servaddr.sin_family=AF_INET;
    servaddr.sin_port=htons(22000);
 
    inet_pton(AF_INET,"192.168.1.2",&(servaddr.sin_addr));
 
    connect(sockfd,(struct sockaddr *)&servaddr,sizeof(servaddr));
 
    int m = 0;
    while(m < 10)
    {
        char snum[5];
        sprintf(snum, "%d", m);
        strcat(sendline, snum);
        write(sockfd,sendline,strlen(sendline)+1);
        m++;
        read(sockfd,recvline,100);
        printf("%s",recvline);
    }
 
}