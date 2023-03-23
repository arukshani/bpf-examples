#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>

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

int getMACAddress(int iNetType, unsigned char chMAC[6]) {

  char *ifname=NULL;
 
  if (!iNetType) {
    ifname="enp65s0f0np0"; /* Ethernet */
  } else {
    ifname="veth1"; /* veth */
  }

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


/* Returns the interface IP Address
   Params: int iNetType - 0: ethernet, 1: Wifi
           char *chIP - IP Address string
   Return: 0: success / -1: Failure
    */
uint32_t getIpAddress(int iNetType) {
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
  strncpy(ifr.ifr_name, "enp65s0f0np0", IFNAMSIZ-1);

  ioctl(fd, SIOCGIFADDR, &ifr);

  /* display result */
  printf("%s\n", inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
  uint32_t ip_addr = inet_addr(inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
  // uint32_t ip_addr = (((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr).s_addr;
  printf("Source IP Address: %d\n", ip_addr);

  close(fd);

  return ip_addr;
}

unsigned char out_eth_src[ETH_ALEN+1];
int src_ip;