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
    struct sockaddr_in server_addr, client_addr;
    char server_message[8000], client_message[8000];
    int client_struct_length = sizeof(client_addr);
    
    // Clean buffers:
    memset(server_message, '\0', sizeof(server_message));
    memset(client_message, '\0', sizeof(client_message));
    
    // Create UDP socket:
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
    
    // Bind to the set port and IP:
    if(bind(socket_desc, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0){
        printf("Couldn't bind to the port\n");
        return -1;
    }
    printf("Done with binding\n");
    
    printf("Listening for incoming messages...\n\n");
    
    // Receive client's message:
    if (recvfrom(socket_desc, client_message, sizeof(client_message), 0,
         (struct sockaddr*)&client_addr, &client_struct_length) < 0){
        printf("Couldn't receive\n");
        return -1;
    }
    // struct timespec receive_time = get_nicclock();
    struct timespec receive_time = get_realtime();
    printf("Received message from IP: %s and port: %i\n",
           inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
    
    printf("Msg from client: %s\n", client_message);
    
    // Respond to client:
    strcpy(server_message, client_message);
    
    // struct timespec send_time = get_nicclock();
    struct timespec send_time = get_realtime();
    if (sendto(socket_desc, server_message, strlen(server_message), 0,
         (struct sockaddr*)&client_addr, client_struct_length) < 0){
        printf("Can't send\n");
        return -1;
    }

    char buff2[100];
    strftime(buff2, sizeof buff2, "%D %T", gmtime(&receive_time.tv_sec));
    printf("yeti03-receive,%ld,%ld,%s\n", receive_time.tv_sec, receive_time.tv_nsec, buff2);

    char buff1[100];
    strftime(buff1, sizeof buff1, "%D %T", gmtime(&send_time.tv_sec));
    printf("yeti03-send,%ld,%ld,%s\n", send_time.tv_sec, send_time.tv_nsec, buff1);

    // Close the socket:
    close(socket_desc);
    
    return 0;
}