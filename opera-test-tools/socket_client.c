#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include<string.h>
 
int main(int argc,char **argv)
{
    int sockfd,n;
    char sendline[100] = "Hello";
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
    while(m < 4000)
    {
        // bzero( sendline, 100);
        // bzero( recvline, 100);
        // fgets(sendline,100,stdin); /*stdin = 0 , for standard input */
        strncpy(sendline, "hello", 100);
        write(sockfd,sendline,strlen(sendline)+1);
        m++;
        // read(sockfd,recvline,100);
        // printf("%s",recvline);
    }
 
}