#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

//https://www.cnx-software.com/2011/04/05/c-code-to-get-mac-address-and-ip-address/ 

/* Returns the MAC Address
   Params: int iNetType - 0: ethernet, 1: veth
           char chMAC[6] - MAC Address in binary format
   Returns: 0: success
           -1: Failure
    */
// int getMACAddress(int iNetType, char chMAC[6]) {
//   struct ifreq ifr;
//   int sock;
//   char *ifname=NULL;
 
//   if (!iNetType) {
//     ifname="enp65s0f0np0"; /* Ethernet */
//   } else {
//     ifname="veth1"; /* veth */
//   }
//   sock=socket(AF_INET,SOCK_DGRAM,0);
//   strcpy( ifr.ifr_name, ifname );
//   ifr.ifr_addr.sa_family = AF_INET;
//   if (ioctl( sock, SIOCGIFHWADDR, &amp;ifr ) &lt; 0) {
//     return -1;
//   }
//   memcpy(chMAC, ifr.ifr_hwaddr.sa_data, 6)
//   close(sock);
//   return 0;
// }

int getMACAddress(char *ifname, unsigned char chMAC[6]) {

  // char *ifname=NULL;
 
  // if (!iNetType) {
  //   ifname="enp65s0f0np0"; /* Ethernet */
  // } else {
  //   ifname="veth1"; /* veth */
  // }

  struct ifreq s;
  int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

  strcpy(s.ifr_name, ifname);
  if (0 == ioctl(fd, SIOCGIFHWADDR, &s)) {
    memcpy(chMAC, s.ifr_hwaddr.sa_data, 6);
    close(fd);
    int i;
    for (i = 0; i < 6; ++i)
      printf(" %02x", (unsigned char) s.ifr_addr.sa_data[i]);
    puts("\n");
    return 0;
  }
  return 1;
}

// void extractIpAddress(unsigned char* sourceString, short* ipAddress)
// {
//     unsigned short len = 0;
//     unsigned char oct[4] = { 0 }, cnt = 0, cnt1 = 0, i, buf[5];

//     len = strlen(sourceString);
//     for (i = 0; i < len; i++) {
//         if (sourceString[i] != '.') {
//             buf[cnt++] = sourceString[i];
//         }
//         if (sourceString[i] == '.' || i == len - 1) {
//             buf[cnt] = '\0';
//             cnt = 0;
//             oct[cnt1++] = atoi(buf);
//         }
//     }
//     ipAddress[0] = oct[0];
//     ipAddress[1] = oct[1];
//     ipAddress[2] = oct[2];
//     ipAddress[3] = oct[3];
// }

// void concatenate_string(char* s, char* s1)
// {
//     int i;
 
//     int j = strlen(s);
 
//     for (i = 0; s1[i] != '\0'; i++) {
//         s[i + j] = s1[i];
//     }
 
//     s[i + j] = '\0';
 
//     return;
// }

// uint32_t veth3_ip_addr;
/* Returns the interface IP Address
   Params: int iNetType - 0: ethernet, 1: Wifi
           char *chIP - IP Address string
   Return: 0: success / -1: Failure
    */
uint32_t getIpAddress(char *ifname) {
//   struct ifreq ifr;
//   int sock = 0;
 
//   sock = socket(AF_INET, SOCK_DGRAM, 0);
//   if(iNetType == 0) {
//     strcpy(ifr.ifr_name, "enp65s0f0np0");
//   } else {
//     strcpy(ifr.ifr_name, "veth1");
//   }
//   if (ioctl(sock, SIOCGIFADDR, ifr) == 0) {
//     strcpy(chIP, "0.0.0.0");
//     return -1;
//  }
//   //  sprintf(chIP, "%s", inet_ntoa(((struct sockaddr_in *) &amp;(ifr.ifr_addr))-&gt;sin_addr));
//   ip_addr = inet_ntoa((struct sockaddr_in *)(ifr.ifr_addr));
//   close(sock);

//  return 0;

  int fd;
  struct ifreq ifr;

  fd = socket(AF_INET, SOCK_DGRAM, 0);

  /* I want to get an IPv4 IP address */
  ifr.ifr_addr.sa_family = AF_INET;

  /* I want IP address attached to "eth0" */
  strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);

  ioctl(fd, SIOCGIFADDR, &ifr);

  /* display result */
  printf("Source IP Address: %s\n", inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
  uint32_t ip_addr = inet_addr(inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
  // uint32_t ip_addr = (((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr).s_addr;
  printf("Source IP Address: %d\n", ip_addr);

//   short veth3_ipAddress[4];
//   extractIpAddress("192.168.2.1", &veth3_ipAddress[0]);
//   char buf[100];
//   int n = sprintf(buf, "%d", veth3_ipAddress[3]);
//   char veth3_subnet_str[100] = "192.168.2.";
//   concatenate_string(veth3_subnet_str, buf);

//   struct sockaddr_in veth3_sa;
//   inet_pton(AF_INET, veth3_subnet_str, &(veth3_sa.sin_addr));
//   veth3_ip_addr = inet_addr(inet_ntoa((veth3_sa.sin_addr)));
//   printf("Source VETH3 IP Address: %s\n", inet_ntoa(veth3_sa.sin_addr));
//   printf("Source VETH3 IP Address: %d\n", veth3_ip_addr);
  close(fd);

  return ip_addr;
}

unsigned char out_eth_src[ETH_ALEN+1];
uint32_t src_ip;

//+++++++++++++++++++READ CSV++++++++++++++++++++++++
const char* getfield(char* line, int num)
{
    const char* tok;
    for (tok = strtok(line, ",");
            tok && *tok;
            tok = strtok(NULL, ",\n"))
    {
        if (!--num)
            return tok;
    }
    return NULL;
}

//+++++++++++++++++++READ routes++++++++++++++++++++++++
const char* getroutefield(char* line, int num)
{
    const char* tok;
    for (tok = strtok(line, " ");
            tok && *tok;
            tok = strtok(NULL, " \n"))
    {
        if (!--num)
            return tok;
    }
    return NULL;
}