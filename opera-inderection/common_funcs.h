#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>

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

unsigned char out_eth_src[ETH_ALEN+1];