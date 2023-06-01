/* 
 * udpclient.c - A simple UDP client
 * usage: udpclient <host> <port>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 
#include <pthread.h>
#include <time.h>
#include <errno.h>

#define BUFSIZE 1024

/* 
 * error - wrapper for perror
 */
void error(char *msg) {
    perror(msg);
    exit(0);
}

struct thread_data
{
  int  thread_id;
  int sockid;
};

int serverlen;
struct sockaddr_in serveraddr;
char readbuf[BUFSIZE];
int sockfd;

void *readMsgs(void *threadarg)
{
    while(1) 
    {
        bzero(readbuf, BUFSIZE);
        // struct thread_data *my_data;   
        // my_data = (struct thread_data *) threadarg;
        printf("hello:\n");
        /* print the server's reply */
        int n = recvfrom(sockfd, readbuf, strlen(readbuf), 0, &serveraddr, &serverlen);
        // printf("%d \n", n);
        // if (n < 0) 
        // error("ERROR in recvfrom");
        if (n > 0)
            printf("Echo from server: %s \n", readbuf);
    }
}

int msleep(long tms)
{
    struct timespec ts;
    int ret;

    if (tms < 0)
    {
        errno = EINVAL;
        return -1;
    }

    ts.tv_sec = tms / 1000;
    ts.tv_nsec = (tms % 1000) * 1000000;

    do {
        ret = nanosleep(&ts, &ts);
    } while (ret && errno == EINTR);

    return ret;
}

int main(int argc, char **argv) {
    int portno, n;
    
    struct hostent *server;
    char *hostname;
    char buf[BUFSIZE];

    /* check command line arguments */
    if (argc != 3) {
       fprintf(stderr,"usage: %s <hostname> <port>\n", argv[0]);
       exit(0);
    }
    hostname = argv[1];
    portno = atoi(argv[2]);

    /* socket: create the socket */
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) 
        error("ERROR opening socket");

    /* gethostbyname: get the server's DNS entry */
    server = gethostbyname(hostname);
    if (server == NULL) {
        fprintf(stderr,"ERROR, no such host as %s\n", hostname);
        exit(0);
    }

    /* build the server's Internet address */
    bzero((char *) &serveraddr, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    bcopy((char *)server->h_addr, 
	  (char *)&serveraddr.sin_addr.s_addr, server->h_length);
    serveraddr.sin_port = htons(portno);

    // pthread_t threads[1];
    // struct thread_data td[1];
    // td[0].thread_id = 0;
    // td[0].sockid = sockfd;

    serverlen = sizeof(serveraddr);

    // int rc = pthread_create(&threads[0], NULL, readMsgs, (void *)&td[0]);
    // if (rc){
    //     printf("Unable to create thread \n");
    //     exit(-1);    
    // }    

    int m = 0;
    while(m < 6400)
    {
        /* get a message from the user */
        bzero(buf, BUFSIZE);
        // printf("Please enter msg: ");
        // fgets(buf, BUFSIZE, stdin);
        char snum[5];
        sprintf(snum, "%d", m);
        strcat(buf, snum);
        m++;

        /* send the message to the server */
        // msleep(1);
        usleep(920);
        n = sendto(sockfd, buf, strlen(buf), 0, &serveraddr, serverlen);
        if (n < 0) 
        error("ERROR in sendto");
        
        /* print the server's reply */
        n = recvfrom(sockfd, buf, strlen(buf), 0, &serveraddr, &serverlen);
        if (n < 0) 
        error("ERROR in recvfrom");
        // printf("Echo from server: %s \n", buf);
    }
    // while (1) sleep(10) ; // would be better
    // sleep(10);
    // pthread_join(threads[0], NULL);
    return 0;
}