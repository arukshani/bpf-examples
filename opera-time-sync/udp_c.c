#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <math.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <time.h>
#include <linux/ptp_clock.h>
#define DEVICE "/dev/ptp2"

#ifndef CLOCK_INVALID
#define CLOCK_INVALID -1
#endif

#define CLOCKFD 3
#define FD_TO_CLOCKID(fd)	((clockid_t) ((((unsigned int) ~fd) << 3) | CLOCKFD))
#define CLOCKID_TO_FD(clk)	((unsigned int) ~((clk) >> 3))

clockid_t clkid;
static clockid_t get_nic_clock_id(void)
{
	int fd;
    char *device = DEVICE;
    clockid_t clkid;

    fd = open(device, O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "opening %s: %s\n", device, strerror(errno));
		return -1;
	}

	clkid = FD_TO_CLOCKID(fd);
	if (CLOCK_INVALID == clkid) {
		fprintf(stderr, "failed to read clock id\n");
		return -1;
	}
	return clkid;
}

static struct timespec get_nicclock(void)
{
	struct timespec ts;
	clock_gettime(clkid, &ts);
	return ts;
}

static struct timespec get_realtime(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_REALTIME, &ts);
	return ts;
}

int main(void){
    int socket_desc;
    struct sockaddr_in server_addr;
    char server_message[8000], client_message[8000];
    int server_struct_length = sizeof(server_addr);
    
    // Clean buffers:
    memset(server_message, '\0', sizeof(server_message));
    memset(client_message, '\0', sizeof(client_message));
    
    // Create socket:
    socket_desc = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    
    if(socket_desc < 0){
        printf("Error while creating socket\n");
        return -1;
    }
    printf("Socket created successfully\n");
    
    // Set port and IP:
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(8000);
    server_addr.sin_addr.s_addr = inet_addr("10.0.0.3");
    
    // Get input from the user:
    printf("Enter message: ");
    gets(client_message);
    
    // struct timespec send_time = get_nicclock();
    struct timespec send_time = get_realtime();
    // Send the message to server:
    if(sendto(socket_desc, client_message, strlen(client_message), 0,
         (struct sockaddr*)&server_addr, server_struct_length) < 0){
        printf("Unable to send message\n");
        return -1;
    }
    
    // Receive the server's response:
    if(recvfrom(socket_desc, server_message, sizeof(server_message), 0,
         (struct sockaddr*)&server_addr, &server_struct_length) < 0){
        printf("Error while receiving server's msg\n");
        return -1;
    }
    // struct timespec receive_time = get_nicclock();
    struct timespec receive_time = get_realtime();
    printf("Server's response: %s\n", server_message);

    char buff1[100];
    strftime(buff1, sizeof buff1, "%D %T", gmtime(&send_time.tv_sec));
    printf("yeti02-send,%ld,%ld,%s\n", send_time.tv_sec, send_time.tv_nsec, buff1);

    char buff2[100];
    strftime(buff2, sizeof buff2, "%D %T", gmtime(&receive_time.tv_sec));
    printf("yeti02-receive,%ld,%ld,%s\n", receive_time.tv_sec, receive_time.tv_nsec, buff2);
    
    // Close the socket:
    close(socket_desc);
    
    return 0;
}